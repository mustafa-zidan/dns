use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::upstream::UpstreamAddr;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub cache: CacheConfig,
    pub blocking: BlockingConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Addresses to listen on. Each address is bound for both UDP and TCP.
    pub listen: Vec<SocketAddr>,
    /// How long an idle TCP connection is kept open.
    pub tcp_idle_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:53".parse().unwrap()],
            tcp_idle_timeout_secs: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Upstream resolvers, tried in order until one answers.
    /// Accepts `1.1.1.1`, `1.1.1.1:53` or `udp://1.1.1.1:53`.
    pub servers: Vec<UpstreamAddr>,
    pub timeout_ms: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: vec!["1.1.1.1:53".parse().unwrap(), "9.9.9.9:53".parse().unwrap()],
            timeout_ms: 2000,
        }
    }
}

impl UpstreamConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_entries: u64,
    /// Lower bound applied to TTLs of cached answers.
    pub min_ttl: u32,
    /// Upper bound applied to TTLs of cached answers.
    pub max_ttl: u32,
    /// TTL for negative answers (NXDOMAIN / NODATA) that carry no SOA record.
    pub negative_ttl: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 10_000,
            min_ttl: 0,
            max_ttl: 86_400,
            negative_ttl: 300,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// Answer blocked names with NXDOMAIN.
    #[default]
    Nxdomain,
    /// Answer A with 0.0.0.0 and AAAA with ::, other types with an empty answer.
    NullIp,
    /// Answer blocked names with REFUSED.
    Refused,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlockingConfig {
    pub enabled: bool,
    pub mode: BlockMode,
    /// TTL of synthesized answers for blocked names.
    pub blocked_ttl: u32,
    /// Blocklist sources: `http(s)://` URLs or local file paths. Hosts files,
    /// plain domain lists and adblock-style `||domain^` rules are supported.
    pub lists: Vec<String>,
    /// Extra domains to block (subdomains included).
    pub denylist: Vec<String>,
    /// Domains that are never blocked (subdomains included). Wins over every list.
    pub allowlist: Vec<String>,
    /// How often blocklist sources are re-downloaded. 0 disables refreshing.
    pub refresh_interval_secs: u64,
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: BlockMode::default(),
            blocked_ttl: 60,
            lists: Vec::new(),
            denylist: Vec::new(),
            allowlist: Vec::new(),
            refresh_interval_secs: 86_400,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing config file {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let config: Config = toml::from_str(text)?;
        anyhow::ensure!(!config.server.listen.is_empty(), "server.listen is empty");
        anyhow::ensure!(
            !config.upstream.servers.is_empty(),
            "upstream.servers is empty"
        );
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_uses_defaults() {
        let config = Config::parse("").unwrap();
        assert_eq!(config.server.listen.len(), 1);
        assert_eq!(config.upstream.servers.len(), 2);
        assert!(config.blocking.enabled);
        assert_eq!(config.blocking.mode, BlockMode::Nxdomain);
    }

    #[test]
    fn parses_full_config() {
        let config = Config::parse(
            r#"
            [server]
            listen = ["127.0.0.1:5353"]

            [upstream]
            servers = ["8.8.8.8", "udp://9.9.9.9:53"]
            timeout_ms = 500

            [cache]
            max_entries = 100

            [blocking]
            mode = "null_ip"
            lists = ["https://example.com/hosts"]
            allowlist = ["example.org"]
            "#,
        )
        .unwrap();
        assert_eq!(config.server.listen[0].port(), 5353);
        assert_eq!(config.upstream.servers[0].to_string(), "udp://8.8.8.8:53");
        assert_eq!(config.blocking.mode, BlockMode::NullIp);
        assert_eq!(config.cache.max_entries, 100);
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::parse("[server]\nlisen = []").is_err());
    }
}
