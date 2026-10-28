//! DNS-over-HTTPS for clients (RFC 8484): GET with a `dns` query parameter
//! or POST with an `application/dns-message` body, over HTTP/2 or HTTP/1.1.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Extension;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hickory_proto::op::Message;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::handler::{Handler, Peer, Transport};
use crate::server::encode_encrypted;

/// ALPN protocol ids, HTTP/2 preferred.
pub const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

const DNS_MESSAGE: &str = "application/dns-message";
/// The largest possible DNS message.
const MAX_MESSAGE: usize = 65_535;

/// Binds DNS-over-HTTPS on every address and serves until a listener fails.
pub async fn serve(
    listen: &[SocketAddr],
    path: &str,
    tls: TlsAcceptor,
    handler: Arc<Handler>,
    idle: Duration,
) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    for &addr in listen {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding DoH {addr}"))?;
        info!(listen = %addr, path, "listening for DNS-over-HTTPS");
        tasks.spawn(serve_listener(
            listener,
            router(path, Arc::clone(&handler)),
            tls.clone(),
            idle,
        ));
    }
    match tasks.join_next().await {
        Some(result) => result?,
        None => Ok(()),
    }
}

/// Binds a DoH listener and serves it. Used by tests that need an ephemeral port.
pub async fn bind(
    addr: SocketAddr,
    path: &str,
    tls: TlsAcceptor,
    handler: Arc<Handler>,
    idle: Duration,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(serve_listener(listener, router(path, handler), tls, idle));
    Ok(local)
}

pub fn router(path: &str, handler: Arc<Handler>) -> Router {
    Router::new()
        .route(path, get(query_get).post(query_post))
        .layer(DefaultBodyLimit::max(MAX_MESSAGE))
        .with_state(handler)
}

async fn serve_listener(
    listener: TcpListener,
    router: Router,
    tls: TlsAcceptor,
    idle: Duration,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let tls = tls.clone();
        // Handlers see the client's address, for per-client rules.
        let service = TowerToHyperService::new(router.clone().layer(Extension(ConnectInfo(peer))));
        tokio::spawn(async move {
            let stream = match timeout(idle, tls.accept(stream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    return debug!(client_ip = %peer.ip(), transport = "doh", error = %e, "TLS handshake failed");
                }
                Err(_) => {
                    return debug!(client_ip = %peer.ip(), transport = "doh", "TLS handshake timed out");
                }
            };
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(idle);
            builder
                .http2()
                .timer(TokioTimer::new())
                .keep_alive_interval(idle)
                .keep_alive_timeout(idle);
            if let Err(e) = builder
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                debug!(client_ip = %peer.ip(), transport = "doh", error = %e, "connection closed");
            }
        });
    }
}

#[derive(Deserialize)]
struct GetParams {
    dns: String,
}

async fn query_get(
    State(handler): State<Arc<Handler>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(params): Query<GetParams>,
) -> Response {
    // RFC 8484 uses unpadded base64url, but accept padding from lenient clients.
    match URL_SAFE_NO_PAD.decode(params.dns.trim_end_matches('=')) {
        Ok(request) if request.len() <= MAX_MESSAGE => answer(&handler, peer, &request).await,
        Ok(_) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, "dns is not base64url").into_response(),
    }
}

async fn query_post(
    State(handler): State<Arc<Handler>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    if content_type != Some(DNS_MESSAGE) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    answer(&handler, peer, &body).await
}

async fn answer(handler: &Handler, peer: SocketAddr, request: &[u8]) -> Response {
    if Message::from_vec(request).is_err() {
        return (StatusCode::BAD_REQUEST, "not a DNS message").into_response();
    }
    let Some(reply) = handler
        .handle_bytes(request, Peer::new(peer.ip(), Transport::Doh))
        .await
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(bytes) = encode_encrypted(&reply) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE)),
            (header::CACHE_CONTROL, cache_control(&reply.message)),
        ],
        bytes,
    )
        .into_response()
}

/// HTTP caches may keep an answer for as long as its shortest TTL (RFC 8484
/// section 5.1). Answers without records are not cached.
fn cache_control(response: &Message) -> HeaderValue {
    let ttl = response
        .answers
        .iter()
        .chain(&response.authorities)
        .map(|record| record.ttl)
        .min();
    match ttl {
        Some(ttl) => HeaderValue::from_str(&format!("max-age={ttl}")).unwrap(),
        None => HeaderValue::from_static("no-store"),
    }
}
