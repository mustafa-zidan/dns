use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use crate::handler::{Handler, Peer, Reply, Transport};
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
        let udp = bind_udp_sockets(addr).with_context(|| format!("binding UDP {addr}"))?;
        let tcp = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding TCP {addr}"))?;
        info!(listen = %addr, udp_sockets = udp.len(), "listening on UDP and TCP");
        for socket in udp {
            tasks.spawn(serve_udp(Arc::new(socket), Arc::clone(&handler)));
        }
        tasks.spawn(serve_tcp(tcp, Arc::clone(&handler), tcp_idle_timeout));
    }
    match tasks.join_next().await {
        Some(result) => result?,
        None => Ok(()),
    }
}

/// Binds UDP sockets and serves them. Used by tests that need an ephemeral port.
pub async fn bind_udp(addr: SocketAddr, handler: Arc<Handler>) -> Result<SocketAddr> {
    let sockets = bind_udp_sockets(addr)?;
    let local = sockets[0].local_addr()?;
    for socket in sockets {
        tokio::spawn(serve_udp(Arc::new(socket), Arc::clone(&handler)));
    }
    Ok(local)
}

/// Binds one UDP socket per worker thread on `addr`. On Linux they share the
/// port with SO_REUSEPORT, and the kernel spreads clients across them, so
/// queries are received in parallel instead of all queueing on one socket.
/// Elsewhere SO_REUSEPORT doesn't spread load, so there's a single socket.
fn bind_udp_sockets(addr: SocketAddr) -> Result<Vec<UdpSocket>> {
    let count = if cfg!(target_os = "linux") {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    } else {
        1
    };
    let first = udp_socket(addr, count > 1)?;
    // Binding port 0 picks a free port, and the other sockets join that one.
    let addr = first.local_addr()?;
    let mut sockets = vec![first];
    for _ in 1..count {
        sockets.push(udp_socket(addr, true)?);
    }
    Ok(sockets)
}

fn udp_socket(addr: SocketAddr, reuse_port: bool) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(reuse_port)?;
    #[cfg(not(target_os = "linux"))]
    let _ = reuse_port;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
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
            let Some(reply) = handler
                .handle_bytes(&request, Peer::new(peer.ip(), Transport::Udp))
                .await
            else {
                return;
            };
            let Some(bytes) = encode_udp(&reply.message, reply.max_udp_payload) else {
                return;
            };
            if let Err(e) = socket.send_to(&bytes, peer).await {
                debug!(client_ip = %peer.ip(), error = %e, "UDP send failed");
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
        info!(listen = %addr, "listening for DNS-over-TLS");
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
            if let Err(e) = serve_stream(stream, peer, handler, idle, Transport::Tcp).await {
                debug!(client_ip = %peer.ip(), transport = "tcp", error = %e, "connection closed");
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
                Ok(Err(e)) => {
                    return debug!(client_ip = %peer.ip(), transport = "dot", error = %e, "TLS handshake failed");
                }
                Err(_) => {
                    return debug!(client_ip = %peer.ip(), transport = "dot", "TLS handshake timed out");
                }
            };
            if let Err(e) = serve_stream(stream, peer, handler, idle, Transport::Dot).await {
                debug!(client_ip = %peer.ip(), transport = "dot", error = %e, "connection closed");
            }
        });
    }
}

/// Queries one TCP or TLS connection may have in flight at once. Past this,
/// the server stops reading from the connection until answers go out.
const MAX_IN_FLIGHT: usize = 32;

/// Serves length-prefixed DNS messages (RFC 1035 section 4.2.2) on a TCP or
/// TLS stream until the client closes it or goes idle. Over TLS, responses
/// are padded for clients that pad their queries.
///
/// Queries are pipelined (RFC 7766, section 6.2.1.1): each one is answered
/// as soon as it is ready, so a query waiting on an upstream doesn't hold
/// up the cached or blocked ones sent after it on the same connection.
async fn serve_stream<S>(
    stream: S,
    peer: SocketAddr,
    handler: Arc<Handler>,
    idle: Duration,
    transport: Transport,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (frames, mut outgoing) = mpsc::channel::<Vec<u8>>(MAX_IN_FLIGHT);
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));

    let read = async move {
        loop {
            let permit = Arc::clone(&in_flight).acquire_owned().await?;
            let len = match timeout(idle, reader.read_u16()).await {
                Ok(Ok(len)) => usize::from(len),
                // Idle timeout or the client closed the connection.
                Ok(Err(_)) | Err(_) => return Ok(()),
            };
            let mut request = vec![0u8; len];
            timeout(idle, reader.read_exact(&mut request)).await??;

            let handler = Arc::clone(&handler);
            let frames = frames.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Some(frame) = answer_frame(&handler, &request, peer, transport).await {
                    // Fails only once the connection is gone.
                    let _ = frames.send(frame).await;
                }
            });
        }
    };
    let write = async move {
        // Ends once the reader and every query it started are done with
        // their senders.
        while let Some(frame) = outgoing.recv().await {
            writer.write_all(&frame).await?;
            writer.flush().await?;
        }
        anyhow::Ok(())
    };
    // An error on either side ends the connection at once. When the client
    // closes or goes idle, the queries already read still get answers.
    tokio::try_join!(read, write)?;
    Ok(())
}

/// Answers one query read from a stream, as a length-prefixed frame.
async fn answer_frame(
    handler: &Handler,
    request: &[u8],
    peer: SocketAddr,
    transport: Transport,
) -> Option<Vec<u8>> {
    let reply = handler
        .handle_bytes(request, Peer::new(peer.ip(), transport))
        .await?;
    let bytes = if transport == Transport::Dot {
        encode_encrypted(&reply)
    } else {
        encode(&reply.message)
    }?;
    let len = u16::try_from(bytes.len()).ok()?;
    let mut frame = Vec::with_capacity(bytes.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&bytes);
    Some(frame)
}

/// Serializes a response for an encrypted transport, padded to the block size
/// RFC 8467 recommends when the client padded its query.
pub fn encode_encrypted(reply: &Reply) -> Option<Vec<u8>> {
    if !reply.pad {
        return encode(&reply.message);
    }
    padding::encode_padded(&reply.message, padding::RESPONSE_BLOCK)
        .inspect_err(|e| error!(error = %e, "failed to encode response"))
        .ok()
}
