//! Plain, unencrypted DNS over UDP and TCP.

use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use hickory_proto::op::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use super::{UpstreamAddr, closed_early, is_response_to};

pub async fn exchange(server: &UpstreamAddr, query: &Message) -> Result<Message> {
    let bytes = query.to_vec()?;
    match server {
        UpstreamAddr::Udp(addr) => {
            let response = udp_exchange(*addr, &bytes, query).await?;
            if response.truncation {
                debug!(upstream = %addr, "truncated upstream answer, retrying over TCP");
                return tcp_exchange(*addr, &bytes, query).await;
            }
            Ok(response)
        }
        UpstreamAddr::Tcp(addr) => tcp_exchange(*addr, &bytes, query).await,
        other => bail!("{other} is not a plain DNS upstream"),
    }
}

async fn udp_exchange(addr: SocketAddr, bytes: &[u8], query: &Message) -> Result<Message> {
    // A fresh socket per query gives every query a random source port.
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(addr).await?;
    socket.send(bytes).await?;

    // Room for the largest possible message, left uninitialized: recv_buf
    // only exposes the bytes it received.
    let mut buf = Vec::with_capacity(65_535);
    loop {
        buf.clear();
        socket.recv_buf(&mut buf).await?;
        match Message::from_vec(&buf) {
            Ok(response) if is_response_to(&response, query) => return Ok(response),
            Ok(_) => debug!(upstream = %addr, "ignoring mismatched upstream answer"),
            Err(e) => debug!(upstream = %addr, error = %e, "ignoring malformed upstream answer"),
        }
    }
}

async fn tcp_exchange(addr: SocketAddr, bytes: &[u8], query: &Message) -> Result<Message> {
    let mut stream = TcpStream::connect(addr).await?;
    match stream_exchange(&mut stream, bytes, query).await {
        Err(e) if closed_early(&e) => {
            debug!(upstream = %addr, error = %e, "upstream closed the connection early, retrying once");
            let mut stream = TcpStream::connect(addr).await?;
            stream_exchange(&mut stream, bytes, query).await
        }
        result => result,
    }
}

/// Sends one length-prefixed query on a stream (TCP or TLS) and reads the answer.
pub async fn stream_exchange<S>(stream: &mut S, bytes: &[u8], query: &Message) -> Result<Message>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let len = u16::try_from(bytes.len()).context("query too large")?;
    let mut frame = Vec::with_capacity(bytes.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(bytes);
    stream.write_all(&frame).await?;
    stream.flush().await?;

    let len = stream.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let response = Message::from_vec(&buf)?;
    if !is_response_to(&response, query) {
        bail!("upstream answer does not match the query");
    }
    Ok(response)
}
