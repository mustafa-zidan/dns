//! DNS-over-TLS (RFC 7858) with a small pool of reused connections.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use hickory_proto::op::Message;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::debug;

use super::bootstrap::Bootstrap;
use super::{Host, closed_early, encode_padded, plain};

/// Idle connections kept per upstream.
const MAX_IDLE: usize = 4;
/// Idle connections older than this are dropped rather than reused, since
/// servers close idle DoT connections after a few seconds.
const MAX_IDLE_AGE: Duration = Duration::from_secs(10);

/// TLS settings shared by all DoT upstreams, verifying certificates against
/// the system trust store.
pub fn client_config() -> Result<ClientConfig> {
    ClientConfig::with_platform_verifier().context("loading TLS trust roots")
}

pub struct TlsUpstream {
    host: Host,
    port: u16,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    bootstrap: Arc<Bootstrap>,
    idle: Mutex<Vec<(TlsStream<TcpStream>, Instant)>>,
}

impl TlsUpstream {
    pub fn new(
        host: Host,
        port: u16,
        tls_name: &str,
        config: Arc<ClientConfig>,
        bootstrap: Arc<Bootstrap>,
    ) -> Result<Self> {
        Ok(Self {
            host,
            port,
            server_name: ServerName::try_from(tls_name.to_owned())?,
            connector: TlsConnector::from(config),
            bootstrap,
            idle: Mutex::new(Vec::new()),
        })
    }

    pub async fn exchange(&self, query: &Message) -> Result<Message> {
        let bytes = encode_padded(query)?;
        if let Some(mut stream) = self.take_idle() {
            match plain::stream_exchange(&mut stream, &bytes, query).await {
                Ok(response) => {
                    self.put_idle(stream);
                    return Ok(response);
                }
                // The server most likely closed it; fall through to a fresh one.
                Err(e) => debug!(error = %e, "reused DoT connection failed"),
            }
        }
        match self.fresh_exchange(&bytes, query).await {
            Err(e) if closed_early(&e) => {
                debug!(error = %e, "DoT upstream closed the connection early, retrying once");
                self.fresh_exchange(&bytes, query).await
            }
            result => result,
        }
    }

    async fn fresh_exchange(&self, bytes: &[u8], query: &Message) -> Result<Message> {
        let mut stream = self.connect().await?;
        let response = plain::stream_exchange(&mut stream, bytes, query).await?;
        self.put_idle(stream);
        Ok(response)
    }

    fn take_idle(&self) -> Option<TlsStream<TcpStream>> {
        let mut idle = self.idle.lock().unwrap();
        while let Some((stream, since)) = idle.pop() {
            if since.elapsed() < MAX_IDLE_AGE {
                return Some(stream);
            }
        }
        None
    }

    fn put_idle(&self, stream: TlsStream<TcpStream>) {
        let mut idle = self.idle.lock().unwrap();
        if idle.len() < MAX_IDLE {
            idle.push((stream, Instant::now()));
        }
    }

    async fn connect(&self) -> Result<TlsStream<TcpStream>> {
        let ips = match &self.host {
            Host::Ip(ip) => vec![*ip],
            Host::Name(name) => self.bootstrap.lookup(name).await?,
        };
        let mut last_err = anyhow!("no addresses for {}", self.host);
        for ip in ips {
            let addr = SocketAddr::new(ip, self.port);
            match TcpStream::connect(addr).await {
                Ok(tcp) => {
                    tcp.set_nodelay(true)?;
                    return self
                        .connector
                        .connect(self.server_name.clone(), tcp)
                        .await
                        .with_context(|| format!("TLS handshake with {addr}"));
                }
                Err(e) => {
                    last_err = anyhow::Error::from(e).context(format!("connecting to {addr}"))
                }
            }
        }
        Err(last_err)
    }
}
