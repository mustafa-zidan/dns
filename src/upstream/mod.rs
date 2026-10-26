//! Upstream resolvers: plain DNS over UDP/TCP, DNS-over-TLS and DNS-over-HTTPS.

mod bootstrap;
mod https;
mod plain;
mod tls;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::EdnsOption;
use serde::Deserialize;
use tokio::time::timeout;
use tracing::warn;

use crate::config::UpstreamConfig;

pub use bootstrap::Bootstrap;

/// EDNS(0) padding option code (RFC 7830).
const EDNS_PADDING: u16 = 12;
/// Queries over encrypted transports are padded to a multiple of this many
/// bytes, the block size RFC 8467 recommends for clients.
const PADDING_BLOCK: usize = 128;

/// Where an encrypted upstream lives: a fixed IP, or a hostname looked up
/// through the bootstrap servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    Name(String),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Name(name) => f.write_str(name),
        }
    }
}

/// An upstream resolver address, as written in the config.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum UpstreamAddr {
    /// Plain DNS over UDP, falling back to TCP for truncated answers.
    Udp(SocketAddr),
    /// Plain DNS over TCP only.
    Tcp(SocketAddr),
    /// DNS-over-TLS (RFC 7858). The certificate is checked against `tls_name`.
    Tls {
        host: Host,
        port: u16,
        tls_name: String,
    },
    /// DNS-over-HTTPS (RFC 8484).
    Https(reqwest::Url),
}

impl UpstreamAddr {
    fn is_plain(&self) -> bool {
        matches!(self, Self::Udp(_) | Self::Tcp(_))
    }

    fn needs_bootstrap(&self) -> bool {
        match self {
            Self::Udp(_) | Self::Tcp(_) => false,
            Self::Tls { host, .. } => matches!(host, Host::Name(_)),
            Self::Https(url) => {
                !matches!(url.host(), Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)))
            }
        }
    }
}

impl FromStr for UpstreamAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parsed = match s.split_once("://") {
            None => parse_socket_addr(s, 53).map(Self::Udp),
            Some(("udp", rest)) => parse_socket_addr(rest, 53).map(Self::Udp),
            Some(("tcp", rest)) => parse_socket_addr(rest, 53).map(Self::Tcp),
            Some(("tls", rest)) => parse_tls(rest),
            Some(("https", _)) => parse_https(s),
            Some((other, _)) => Err(anyhow!("unsupported scheme {other:?}")),
        };
        parsed.with_context(|| format!("invalid upstream {s:?}"))
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
            Self::Tls {
                host,
                port,
                tls_name,
            } => {
                write!(f, "tls://{host}:{port}")?;
                match host {
                    Host::Name(name) if name == tls_name => Ok(()),
                    Host::Ip(ip) if ip.to_string() == *tls_name => Ok(()),
                    _ => write!(f, "#{tls_name}"),
                }
            }
            Self::Https(url) => write!(f, "{url}"),
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

/// Parses `host[:port][#tls-name]`, e.g. `1.1.1.1#cloudflare-dns.com` or `dns.quad9.net`.
fn parse_tls(rest: &str) -> Result<UpstreamAddr> {
    let (endpoint, tls_name) = match rest.split_once('#') {
        Some((endpoint, name)) => (endpoint, Some(name)),
        None => (rest, None),
    };
    let (host, port) = if let Ok(addr) = parse_socket_addr(endpoint, 853) {
        (Host::Ip(addr.ip()), addr.port())
    } else {
        let (name, port) = match endpoint.rsplit_once(':') {
            Some((name, port)) => (name, port.parse().context("invalid port")?),
            None => (endpoint, 853),
        };
        ensure!(is_hostname(name), "not an IP address or hostname");
        (Host::Name(name.to_ascii_lowercase()), port)
    };
    let tls_name = match (tls_name, &host) {
        (Some(name), _) => name.to_ascii_lowercase(),
        (None, Host::Ip(ip)) => ip.to_string(),
        (None, Host::Name(name)) => name.clone(),
    };
    rustls::pki_types::ServerName::try_from(tls_name.as_str())
        .with_context(|| format!("invalid TLS name {tls_name:?}"))?;
    Ok(UpstreamAddr::Tls {
        host,
        port,
        tls_name,
    })
}

fn parse_https(s: &str) -> Result<UpstreamAddr> {
    let url = reqwest::Url::parse(s)?;
    ensure!(url.host().is_some(), "missing host");
    ensure!(url.fragment().is_none(), "URL fragments are not allowed");
    Ok(UpstreamAddr::Https(url))
}

fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

enum Transport {
    Plain(UpstreamAddr),
    Tls(tls::TlsUpstream),
    Https(https::HttpsUpstream),
}

struct Server {
    addr: UpstreamAddr,
    transport: Transport,
}

impl Server {
    async fn exchange(&self, query: &Message) -> Result<Message> {
        match &self.transport {
            Transport::Plain(addr) => plain::exchange(addr, query).await,
            Transport::Tls(upstream) => upstream.exchange(query).await,
            Transport::Https(upstream) => upstream.exchange(query).await,
        }
    }
}

/// Forwards queries to a list of upstream resolvers with failover.
pub struct Upstreams {
    servers: Vec<Server>,
    timeout: Duration,
}

impl Upstreams {
    /// Builds the upstreams, verifying DoT/DoH certificates against the system trust store.
    pub fn new(config: &UpstreamConfig) -> Result<Self> {
        Self::with_tls_config(config, tls::client_config()?)
    }

    /// Builds the upstreams with custom TLS settings, e.g. extra trust roots.
    pub fn with_tls_config(
        config: &UpstreamConfig,
        tls_config: rustls::ClientConfig,
    ) -> Result<Self> {
        ensure!(
            config.bootstrap.iter().all(UpstreamAddr::is_plain),
            "upstream.bootstrap only accepts plain udp:// or tcp:// servers"
        );
        let bootstrap = Arc::new(Bootstrap::new(config.bootstrap.clone(), config.timeout()));
        let tls_config = Arc::new(tls_config);

        let mut servers = Vec::with_capacity(config.servers.len());
        for addr in &config.servers {
            if addr.needs_bootstrap() && config.bootstrap.is_empty() {
                bail!("upstream {addr} is a hostname, so upstream.bootstrap must not be empty");
            }
            let transport = match addr {
                UpstreamAddr::Udp(_) | UpstreamAddr::Tcp(_) => Transport::Plain(addr.clone()),
                UpstreamAddr::Tls {
                    host,
                    port,
                    tls_name,
                } => Transport::Tls(tls::TlsUpstream::new(
                    host.clone(),
                    *port,
                    tls_name,
                    Arc::clone(&tls_config),
                    Arc::clone(&bootstrap),
                )?),
                UpstreamAddr::Https(url) => Transport::Https(https::HttpsUpstream::new(
                    url.clone(),
                    &tls_config,
                    Arc::clone(&bootstrap),
                )?),
            };
            servers.push(Server {
                addr: addr.clone(),
                transport,
            });
        }
        Ok(Self {
            servers,
            timeout: config.timeout(),
        })
    }

    /// Sends `query` to each upstream in order and returns the first valid response.
    pub async fn resolve(&self, query: &Message) -> Result<Message> {
        let mut last_err = anyhow!("no upstream servers configured");
        for server in &self.servers {
            match timeout(self.timeout, server.exchange(query)).await {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(e)) => {
                    warn!(server = %server.addr, error = %format!("{e:#}"), "upstream query failed");
                    last_err = e;
                }
                Err(_) => {
                    warn!(server = %server.addr, "upstream query timed out");
                    last_err = anyhow!("timed out querying {}", server.addr);
                }
            }
        }
        Err(last_err)
    }
}

/// Serializes a query for an encrypted transport, padded so its length does
/// not give away which name is being looked up.
fn encode_padded(query: &Message) -> Result<Vec<u8>> {
    let mut query = query.clone();
    let unpadded = query.to_vec()?.len();
    let Some(edns) = query.edns.as_mut() else {
        return Ok(query.to_vec()?);
    };
    // The option itself adds 4 bytes (code + length) before its payload.
    let padding = (PADDING_BLOCK - (unpadded + 4) % PADDING_BLOCK) % PADDING_BLOCK;
    edns.options_mut()
        .insert(EdnsOption::Unknown(EDNS_PADDING, vec![0; padding]));
    Ok(query.to_vec()?)
}

/// Checks that `response` answers `query`: same ID and the same question.
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
    use hickory_proto::op::{Edns, Query};
    use hickory_proto::rr::{Name, RecordType};

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
            ("tls://1.1.1.1", "tls://1.1.1.1:853"),
            (
                "tls://1.1.1.1#cloudflare-dns.com",
                "tls://1.1.1.1:853#cloudflare-dns.com",
            ),
            ("tls://dns.quad9.net", "tls://dns.quad9.net:853"),
            ("tls://Dns.Quad9.net:8853", "tls://dns.quad9.net:8853"),
            (
                "tls://[2620:fe::fe]:853#dns.quad9.net",
                "tls://[2620:fe::fe]:853#dns.quad9.net",
            ),
            (
                "https://cloudflare-dns.com/dns-query",
                "https://cloudflare-dns.com/dns-query",
            ),
            ("https://1.1.1.1/dns-query", "https://1.1.1.1/dns-query"),
        ];
        for (input, expected) in cases {
            let addr: UpstreamAddr = input.parse().unwrap();
            assert_eq!(addr.to_string(), expected, "input {input}");
        }
    }

    #[test]
    fn rejects_bad_upstreams() {
        for input in [
            "example.com",
            "quic://1.1.1.1",
            "tls://",
            "tls://bad_host!",
            "tls://1.1.1.1#",
            "https://",
            "https://dns.example/q#frag",
        ] {
            assert!(input.parse::<UpstreamAddr>().is_err(), "input {input}");
        }
    }

    #[test]
    fn knows_which_upstreams_need_bootstrap() {
        let needs = |s: &str| s.parse::<UpstreamAddr>().unwrap().needs_bootstrap();
        assert!(!needs("1.1.1.1"));
        assert!(!needs("tls://1.1.1.1#cloudflare-dns.com"));
        assert!(needs("tls://dns.quad9.net"));
        assert!(needs("https://dns.quad9.net/dns-query"));
        assert!(!needs("https://1.1.1.1/dns-query"));
        assert!(!needs("https://[2606:4700:4700::1111]/dns-query"));
    }

    #[test]
    fn pads_encrypted_queries_to_block_size() {
        for name in ["a.io.", "a-much-longer-name.subdomain.example.com."] {
            let mut query = Message::query();
            query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            query.set_edns(Edns::new());
            let bytes = encode_padded(&query).unwrap();
            assert_eq!(bytes.len() % PADDING_BLOCK, 0, "name {name}");
        }
    }

    #[test]
    fn rejects_encrypted_hostnames_without_bootstrap() {
        let config = UpstreamConfig {
            servers: vec!["tls://dns.quad9.net".parse().unwrap()],
            bootstrap: vec![],
            ..UpstreamConfig::default()
        };
        assert!(Upstreams::new(&config).is_err());

        let config = UpstreamConfig {
            bootstrap: vec!["tls://1.1.1.1".parse().unwrap()],
            ..UpstreamConfig::default()
        };
        assert!(Upstreams::new(&config).is_err());
    }
}
