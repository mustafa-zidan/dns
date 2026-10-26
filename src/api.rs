//! HTTP API for stats and runtime control.
//!
//! | Method | Path                    | What it does                                   |
//! |--------|-------------------------|------------------------------------------------|
//! | GET    | `/api/health`           | Liveness check                                 |
//! | GET    | `/api/stats?top=N`      | Query counters and top domains                 |
//! | DELETE | `/api/stats`            | Reset the counters                             |
//! | GET    | `/api/blocking`         | Blocking state, rule counts, per-list status   |
//! | PUT    | `/api/blocking`         | `{"enabled": bool, "pause_secs": n}`           |
//! | POST   | `/api/blocking/reload`  | Re-download the blocklists now                 |
//! | GET    | `/api/check?name=x`     | Whether a name is blocked, and by which rule   |
//! | GET    | `/api/cache`            | Number of cached answers                       |
//! | DELETE | `/api/cache`            | Empty the cache                                |
//!
//! The web dashboard is served at `/` from the same address, unless
//! `api.dashboard` is off.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::blocklist::{Blocklist, SourceStatus, Verdict};
use crate::cache::Cache;
use crate::stats::{Snapshot, Stats};

const DEFAULT_TOP: usize = 10;
const MAX_TOP: usize = 100;

#[derive(Clone)]
pub struct ApiState {
    pub blocklist: Arc<Blocklist>,
    pub cache: Arc<Cache>,
    pub stats: Arc<Stats>,
    pub token: Option<Arc<str>>,
    pub dashboard: bool,
}

/// Binds the API and serves it until the listener fails.
pub async fn serve(listen: SocketAddr, state: ApiState) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding API on {listen}"))?;
    if state.token.is_none() && !listen.ip().is_loopback() {
        warn!(%listen, "the API is reachable from the network without a token; set api.token");
    }
    info!(%listen, "API listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

pub fn router(state: ApiState) -> Router {
    let api = Router::new()
        .route("/stats", get(get_stats).delete(reset_stats))
        .route("/blocking", get(get_blocking).put(set_blocking))
        .route("/blocking/reload", post(reload_blocking))
        .route("/check", get(check))
        .route("/cache", get(get_cache).delete(clear_cache))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));
    let mut router = Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .nest("/api", api);
    if state.dashboard {
        router = router
            .route(
                "/",
                get(|| async { asset(INDEX_HTML, "text/html; charset=utf-8") }),
            )
            .route(
                "/app.js",
                get(|| async { asset(APP_JS, "text/javascript; charset=utf-8") }),
            )
            .route(
                "/app.css",
                get(|| async { asset(APP_CSS, "text/css; charset=utf-8") }),
            );
    }
    router
        .layer(middleware::from_fn_with_state(state.clone(), guard_browser))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

const INDEX_HTML: &str = include_str!("ui/index.html");
const APP_JS: &str = include_str!("ui/app.js");
const APP_CSS: &str = include_str!("ui/app.css");

/// The dashboard loads nothing from other origins, so the policy allows only
/// its own script, stylesheet and API calls.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
    style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; \
    form-action 'none'; frame-ancestors 'none'";

fn asset(body: &'static str, content_type: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

/// Stops other web pages from driving the API through the visitor's browser.
///
/// A request with an `Origin` must come from the API's own origin, which
/// blocks cross-site form posts. Without a token, the `Host` must also be an
/// IP address or `localhost`: a page on a hostile domain that it re-points at
/// 127.0.0.1 (DNS rebinding) still sends its own name as the host.
async fn guard_browser(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    if state.token.is_none() && !host.is_some_and(is_ip_or_localhost) {
        return (StatusCode::FORBIDDEN, "set api.token to use a hostname").into_response();
    }
    if !same_origin(headers, host) {
        return (StatusCode::FORBIDDEN, "cross-origin request").into_response();
    }
    next.run(request).await
}

fn same_origin(headers: &HeaderMap, host: Option<&str>) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let origin = origin.to_str().unwrap_or_default();
    let origin = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"));
    origin.is_some() && origin == host
}

/// Whether a `Host` header value, with or without a port, names an IP
/// address or `localhost`.
fn is_ip_or_localhost(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or(rest, |(ip, _)| ip),
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };
    name.eq_ignore_ascii_case("localhost") || name.parse::<IpAddr>().is_ok()
}

async fn require_token(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let Some(token) = &state.token else {
        return next.run(request).await;
    };
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(presented) if constant_time_eq(presented.as_bytes(), token.as_bytes()) => {
            next.run(request).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "missing or invalid token",
        )
            .into_response(),
    }
}

/// Compares without returning early, so response timing does not reveal how
/// much of the token was right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
struct TopParams {
    top: Option<usize>,
}

async fn get_stats(
    State(state): State<ApiState>,
    Query(params): Query<TopParams>,
) -> Json<Snapshot> {
    let top = params.top.unwrap_or(DEFAULT_TOP).min(MAX_TOP);
    Json(state.stats.snapshot(top))
}

async fn reset_stats(State(state): State<ApiState>) -> StatusCode {
    state.stats.reset();
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
struct BlockingStatus {
    /// Whether queries are being blocked right now.
    active: bool,
    /// Seconds left on a pause, if blocking is paused.
    paused_for_secs: Option<u64>,
    blocked_domains: usize,
    allowed_domains: usize,
    /// Unix time of the last list reload.
    last_reload: Option<u64>,
    sources: Vec<SourceStatus>,
}

fn blocking_status(blocklist: &Blocklist) -> BlockingStatus {
    let rules = blocklist.rules();
    BlockingStatus {
        active: blocklist.enabled(),
        paused_for_secs: blocklist.paused_for().map(|d| d.as_secs()),
        blocked_domains: rules.blocked.len(),
        allowed_domains: rules.allowed.len(),
        last_reload: blocklist
            .last_reload()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
        sources: blocklist.sources().to_vec(),
    }
}

async fn get_blocking(State(state): State<ApiState>) -> Json<BlockingStatus> {
    Json(blocking_status(&state.blocklist))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetBlocking {
    enabled: bool,
    /// With `enabled: false`, turn blocking back on after this many seconds.
    pause_secs: Option<u64>,
}

async fn set_blocking(
    State(state): State<ApiState>,
    Json(body): Json<SetBlocking>,
) -> Result<Json<BlockingStatus>, (StatusCode, &'static str)> {
    match (body.enabled, body.pause_secs) {
        (true, Some(_)) => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "pause_secs only applies when enabled is false",
            ));
        }
        (false, Some(secs)) => state.blocklist.pause(Duration::from_secs(secs)),
        (enabled, None) => state.blocklist.set_enabled(enabled),
    }
    info!(
        enabled = body.enabled,
        pause_secs = body.pause_secs,
        "blocking changed through the API"
    );
    Ok(Json(blocking_status(&state.blocklist)))
}

async fn reload_blocking(State(state): State<ApiState>) -> Json<BlockingStatus> {
    state.blocklist.reload().await;
    Json(blocking_status(&state.blocklist))
}

#[derive(Deserialize)]
struct CheckParams {
    name: String,
}

#[derive(Serialize)]
struct CheckResult {
    name: String,
    /// Whether the rules match, regardless of whether blocking is active.
    blocked: bool,
    rule: Option<String>,
}

async fn check(
    State(state): State<ApiState>,
    Query(params): Query<CheckParams>,
) -> Json<CheckResult> {
    let name = params
        .name
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let rules = state.blocklist.rules();
    let rule = match rules.check(&name) {
        Verdict::Blocked(rule) => Some(rule.to_string()),
        Verdict::Allowed => None,
    };
    Json(CheckResult {
        blocked: rule.is_some(),
        name,
        rule,
    })
}

#[derive(Serialize)]
struct CacheStatus {
    entries: u64,
}

async fn get_cache(State(state): State<ApiState>) -> Json<CacheStatus> {
    Json(CacheStatus {
        entries: state.cache.len(),
    })
}

async fn clear_cache(State(state): State<ApiState>) -> StatusCode {
    state.cache.clear();
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_tokens() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
    }

    #[test]
    fn recognises_ip_hosts() {
        for host in [
            "127.0.0.1:8053",
            "192.168.1.2",
            "[::1]:8053",
            "localhost:8053",
            "LOCALHOST",
        ] {
            assert!(is_ip_or_localhost(host), "{host}");
        }
        for host in ["evil.example:8053", "dns.lan", "127.0.0.1.nip.io", ""] {
            assert!(!is_ip_or_localhost(host), "{host}");
        }
    }

    #[test]
    fn compares_origins() {
        let with = |origin: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            headers
        };
        let host = Some("127.0.0.1:8053");
        assert!(same_origin(&HeaderMap::new(), host));
        assert!(same_origin(&with("http://127.0.0.1:8053"), host));
        assert!(!same_origin(&with("http://evil.example"), host));
        assert!(!same_origin(&with("null"), host));
    }
}
