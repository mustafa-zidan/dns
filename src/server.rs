use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use crate::handler::{Handler, client_max_payload};
use crate::padding;

/// ALPN protocol id for DNS-over-TLS (RFC 7858).
pub const DOT_ALPN: &[u8] = b"dot";

/// Binds UDP and TCP on every address and serves until an error stops a listener.
pub async fn serve(
    listen: &[SocketAddr],
    handler: Arc<Handler>,
    tcp_idle_timeout: Duration,
) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    for &addr in listen {
        let udp = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding UDP {addr}"))?;
        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding TCP {addr}"))?;
        info!(%addr, "listening on UDP and TCP");
        tasks.spawn(serve_udp(Arc::new(udp), Arc::clone(&handler)));
        tasks.spawn(serve_tcp(tcp, Arc::clone(&handler), tcp_idle_timeout));
    }
    match tasks.join_next().await {
        Some(result) => result?,
        None => Ok(()),
    }
}

/// Binds a UDP socket and serves it. Used by tests that need an ephemeral port.
pub async fn bind_udp(addr: SocketAddr, handler: Arc<Handler>) -> Result<SocketAddr> {
    let socket = UdpSocket::bind(addr).await?;
    let local = socket.local_addr()?;
    tokio::spawn(serve_udp(Arc::new(socket), handler));
    Ok(local)
}

/// Binds a TCP listener and serves it. Used by tests that need an ephemeral port.
pub async fn bind_tcp(
    addr: SocketAddr,
    handler: Arc<Handler>,
    idle: Duration,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(serve_tcp(listener, handler, idle));
    Ok(local)
}

async fn serve_udp(socket: Arc<UdpSocket>, handler: Arc<Handler>) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(e) => {
                // ICMP errors from earlier sends surface here on some platforms.
                debug!(error = %e, "UDP receive error");
                continue;
            }
        };
        let request = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let Some(response) = handler.handle_bytes(&request).await else {
                return;
            };
            let Some(bytes) = encode_udp(&response, client_max_payload(&request)) else {
                return;
            };
            if let Err(e) = socket.send_to(&bytes, peer).await {
                debug!(%peer, error = %e, "UDP send failed");
            }
        });
    }
}

/// Serializes a response, truncating it (TC bit) if it is larger than the client accepts.
fn encode_udp(response: &Message, max_payload: usize) -> Option<Vec<u8>> {
    let bytes = encode(response)?;
    if bytes.len() <= max_payload {
        return Some(bytes);
    }
    encode(&response.truncate())
}

fn encode(response: &Message) -> Option<Vec<u8>> {
    response
        .to_vec()
        .inspect_err(|e| error!(error = %e, "failed to encode response"))
        .ok()
}

/// Binds DNS-over-TLS on every address and serves until a listener fails.
pub async fn serve_dot(
    listen: &[SocketAddr],
    tls: TlsAcceptor,
    handler: Arc<Handler>,
    idle: Duration,
) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    for &addr in listen {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding DoT {addr}"))?;
        info!(%addr, "listening for DNS-over-TLS");
        tasks.spawn(serve_dot_listener(
            listener,
            tls.clone(),
            Arc::clone(&handler),
            idle,
        ));
    }
    match tasks.join_next().await {
        Some(result) => result?,
        None => Ok(()),
    }
}

/// Binds a DoT listener and serves it. Used by tests that need an ephemeral port.
pub async fn bind_dot(
    addr: SocketAddr,
    tls: TlsAcceptor,
    handler: Arc<Handler>,
    idle: Duration,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(serve_dot_listener(listener, tls, handler, idle));
    Ok(local)
}

async fn serve_tcp(listener: TcpListener, handler: Arc<Handler>, idle: Duration) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            if let Err(e) = serve_stream(stream, handler, idle, false).await {
                debug!(%peer, error = %e, "TCP connection closed");
            }
        });
    }
}

async fn serve_dot_listener(
    listener: TcpListener,
    tls: TlsAcceptor,
    handler: Arc<Handler>,
    idle: Duration,
) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let tls = tls.clone();
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            // The handshake gets the same deadline as an idle connection, so
            // a client that connects and stalls can't hold a task open.
            let stream = match timeout(idle, tls.accept(stream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => return debug!(%peer, error = %e, "DoT handshake failed"),
                Err(_) => return debug!(%peer, "DoT handshake timed out"),
            };
            if let Err(e) = serve_stream(stream, handler, idle, true).await {
                debug!(%peer, error = %e, "DoT connection closed");
            }
        });
    }
}

/// Serves length-prefixed DNS messages (RFC 1035 section 4.2.2) on a TCP or
/// TLS stream until the client closes it or goes idle. Over TLS, responses
/// are padded for clients that pad their queries.
async fn serve_stream<S>(
    mut stream: S,
    handler: Arc<Handler>,
    idle: Duration,
    encrypted: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let len = match timeout(idle, stream.read_u16()).await {
            Ok(Ok(len)) => usize::from(len),
            // Idle timeout or the client closed the connection.
            Ok(Err(_)) | Err(_) => return Ok(()),
        };
        let mut request = vec![0u8; len];
        timeout(idle, stream.read_exact(&mut request)).await??;

        let Some(response) = handler.handle_bytes(&request).await else {
            return Ok(());
        };
        let bytes = if encrypted {
            encode_encrypted(&request, &response)
        } else {
            encode(&response)
        };
        let Some(bytes) = bytes else {
            return Ok(());
        };
        let len = u16::try_from(bytes.len())?;
        let mut frame = Vec::with_capacity(bytes.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&bytes);
        stream.write_all(&frame).await?;
        stream.flush().await?;
    }
}

/// Serializes a response for an encrypted transport, padded to the block size
/// RFC 8467 recommends when the client padded its query.
pub fn encode_encrypted(request: &[u8], response: &Message) -> Option<Vec<u8>> {
    let padded = Message::from_vec(request).is_ok_and(|q| padding::requested(&q));
    if !padded {
        return encode(response);
    }
    padding::encode_padded(response, padding::RESPONSE_BLOCK)
        .inspect_err(|e| error!(error = %e, "failed to encode response"))
        .ok()
}
