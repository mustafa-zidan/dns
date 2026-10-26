use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use hickory_proto::op::Message;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, warn};

/// An upstream resolver address.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum UpstreamAddr {
    /// Plain DNS over UDP, falling back to TCP for truncated answers.
    Udp(SocketAddr),
    /// Plain DNS over TCP only.
    Tcp(SocketAddr),
}

impl FromStr for UpstreamAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (scheme, rest) = match s.split_once("://") {
            Some((scheme, rest)) => (scheme, rest),
            None => ("udp", s),
        };
        let addr = parse_socket_addr(rest, 53)
            .with_context(|| format!("invalid upstream address {s:?}"))?;
        match scheme {
            "udp" => Ok(Self::Udp(addr)),
            "tcp" => Ok(Self::Tcp(addr)),
            other => bail!("unsupported upstream scheme {other:?} in {s:?}"),
        }
    }
}

impl TryFrom<String> for UpstreamAddr {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl fmt::Display for UpstreamAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "udp://{addr}"),
            Self::Tcp(addr) => write!(f, "tcp://{addr}"),
        }
    }
}

fn parse_socket_addr(s: &str, default_port: u16) -> Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let ip = s.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = ip.parse().map_err(|_| anyhow!("not an IP address"))?;
    Ok(SocketAddr::new(ip, default_port))
}

/// Forwards queries to a list of upstream resolvers with failover.
pub struct Upstreams {
    servers: Vec<UpstreamAddr>,
    timeout: Duration,
}

impl Upstreams {
    pub fn new(servers: Vec<UpstreamAddr>, timeout: Duration) -> Self {
        Self { servers, timeout }
    }

    /// Sends `query` to each upstream in order and returns the first valid response.
    pub async fn resolve(&self, query: &Message) -> Result<Message> {
        let bytes = query.to_vec()?;
        let mut last_err = anyhow!("no upstream servers configured");
        for server in &self.servers {
            match timeout(self.timeout, exchange(server, &bytes, query)).await {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(e)) => {
                    warn!(%server, error = %e, "upstream query failed");
                    last_err = e;
                }
                Err(_) => {
                    warn!(%server, "upstream query timed out");
                    last_err = anyhow!("timed out querying {server}");
                }
            }
        }
        Err(last_err)
    }
}

async fn exchange(server: &UpstreamAddr, bytes: &[u8], query: &Message) -> Result<Message> {
    match server {
        UpstreamAddr::Udp(addr) => {
            let response = udp_exchange(*addr, bytes, query).await?;
            if response.truncation {
                debug!(%addr, "truncated upstream answer, retrying over TCP");
                return tcp_exchange(*addr, bytes, query).await;
            }
            Ok(response)
        }
        UpstreamAddr::Tcp(addr) => tcp_exchange(*addr, bytes, query).await,
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

    let mut buf = vec![0u8; 65_535];
    loop {
        let len = socket.recv(&mut buf).await?;
        match Message::from_vec(&buf[..len]) {
            Ok(response) if is_response_to(&response, query) => return Ok(response),
            Ok(_) => debug!(%addr, "ignoring mismatched upstream answer"),
            Err(e) => debug!(%addr, error = %e, "ignoring malformed upstream answer"),
        }
    }
}

async fn tcp_exchange(addr: SocketAddr, bytes: &[u8], query: &Message) -> Result<Message> {
    let mut stream = TcpStream::connect(addr).await?;
    let len = u16::try_from(bytes.len()).context("query too large")?;
    let mut frame = Vec::with_capacity(bytes.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(bytes);
    stream.write_all(&frame).await?;

    let len = stream.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let response = Message::from_vec(&buf)?;
    if !is_response_to(&response, query) {
        bail!("upstream answer does not match the query");
    }
    Ok(response)
}

fn is_response_to(response: &Message, query: &Message) -> bool {
    response.id == query.id
        && response.queries.len() == query.queries.len()
        && response.queries.iter().zip(&query.queries).all(|(a, b)| {
            a.query_type() == b.query_type()
                && a.query_class() == b.query_class()
                && a.name().eq_ignore_root(b.name())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_upstream_addresses() {
        let cases = [
            ("1.1.1.1", "udp://1.1.1.1:53"),
            ("1.1.1.1:5353", "udp://1.1.1.1:5353"),
            ("udp://9.9.9.9", "udp://9.9.9.9:53"),
            ("tcp://9.9.9.9:53", "tcp://9.9.9.9:53"),
            ("2606:4700:4700::1111", "udp://[2606:4700:4700::1111]:53"),
            (
                "[2606:4700:4700::1111]:53",
                "udp://[2606:4700:4700::1111]:53",
            ),
        ];
        for (input, expected) in cases {
            let addr: UpstreamAddr = input.parse().unwrap();
            assert_eq!(addr.to_string(), expected, "input {input}");
        }
    }

    #[test]
    fn rejects_bad_upstreams() {
        assert!("example.com".parse::<UpstreamAddr>().is_err());
        assert!("quic://1.1.1.1".parse::<UpstreamAddr>().is_err());
    }
}
