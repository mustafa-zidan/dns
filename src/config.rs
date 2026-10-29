use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use ipnet::IpNet;
use jiff::civil::{Time, Weekday};
use serde::Deserialize;

use crate::auth::{self, Role};
use crate::upstream::UpstreamAddr;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub upstream: UpstreamConfig,
    pub cache: CacheConfig,
    pub blocking: BlockingConfig,
    pub api: ApiConfig,
    pub stats: StatsConfig,
    /// Rules for specific devices or networks, picked by source address.
    pub clients: Vec<ClientConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Addresses to listen on. Each address is bound for both UDP and TCP.
    pub listen: Vec<SocketAddr>,
    /// How long an idle TCP connection is kept open.
    pub tcp_idle_timeout_secs: u64,
    /// IANA time zone for client schedules, such as `Europe/Berlin`. Unset
    /// uses the system's zone (the `TZ` variable or `/etc/localtime`).
    pub timezone: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:53".parse().unwrap()],
            tcp_idle_timeout_secs: 10,
            timezone: None,
        }
    }
}

/// Encrypted DNS for clients: DNS-over-TLS and DNS-over-HTTPS listeners
/// sharing one certificate.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain, leaf first, such as Let's Encrypt's fullchain.pem.
    pub cert_file: Option<PathBuf>,
    /// PEM private key for the certificate.
    pub key_file: Option<PathBuf>,
    /// DNS-over-TLS (RFC 7858) listeners, usually port 853.
    pub dot_listen: Vec<SocketAddr>,
    /// DNS-over-HTTPS (RFC 8484) listeners, usually port 443.
    pub doh_listen: Vec<SocketAddr>,
    /// URL path DoH clients send queries to.
    pub doh_path: String,
    /// How often to check the certificate files for a renewed certificate.
    pub reload_interval_secs: u64,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_file: None,
            key_file: None,
            dot_listen: Vec::new(),
            doh_listen: Vec::new(),
            doh_path: "/dns-query".into(),
            reload_interval_secs: 3600,
        }
    }
}

impl TlsConfig {
    pub fn enabled(&self) -> bool {
        !self.dot_listen.is_empty() || !self.doh_listen.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Upstream resolvers, tried in order until one answers. Accepts plain
    /// DNS (`1.1.1.1`, `udp://1.1.1.1:53`, `tcp://1.1.1.1`), DNS-over-TLS
    /// (`tls://1.1.1.1#cloudflare-dns.com`, `tls://dns.quad9.net`) and
    /// DNS-over-HTTPS (`https://cloudflare-dns.com/dns-query`).
    pub servers: Vec<UpstreamAddr>,
    /// Plain DNS servers used only to look up the hostnames of encrypted
    /// upstreams. Not needed when every encrypted upstream is given by IP.
    pub bootstrap: Vec<UpstreamAddr>,
    pub timeout_ms: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                "tls://1.1.1.1#cloudflare-dns.com".parse().unwrap(),
                "tls://9.9.9.9#dns.quad9.net".parse().unwrap(),
            ],
            bootstrap: vec!["1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()],
            timeout_ms: 3000,
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

/// A group of clients, matched by source address, with its own rules.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Shown in logs and API answers.
    pub name: String,
    /// IP addresses (`192.168.1.20`) and networks (`192.168.1.64/28`). When a
    /// client matches several groups, the most specific network wins.
    #[serde(deserialize_with = "deserialize_nets")]
    pub addresses: Vec<IpNet>,
    /// Apply the shared `[blocking]` lists, denylist and allowlist.
    #[serde(default = "default_true")]
    pub blocklists: bool,
    /// Domains blocked for these clients only (subdomains included).
    #[serde(default)]
    pub denylist: Vec<String>,
    /// Domains never blocked for these clients (subdomains included). Wins
    /// over every other rule, schedules included.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Blocklist sources for these clients only, in the same formats as
    /// `blocking.lists`. Refreshed along with the shared lists.
    #[serde(default)]
    pub lists: Vec<String>,
    /// Time windows with extra rules, such as a bedtime.
    #[serde(default)]
    pub schedules: Vec<ScheduleConfig>,
}

/// A weekly time window during which a client group gets extra rules.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleConfig {
    /// Days the window starts on (`mon` to `sun`). Default: every day.
    #[serde(default = "every_day", deserialize_with = "deserialize_days")]
    pub days: Vec<Weekday>,
    /// Start time, `HH:MM`, in `server.timezone`.
    #[serde(deserialize_with = "deserialize_time")]
    pub from: Time,
    /// End time, `HH:MM`. Earlier than `from` means the window runs past
    /// midnight into the next day.
    #[serde(deserialize_with = "deserialize_time")]
    pub to: Time,
    /// Block every name except the group's allowlist.
    #[serde(default)]
    pub block_all: bool,
    /// Domains blocked during the window (subdomains included).
    #[serde(default)]
    pub denylist: Vec<String>,
}

fn every_day() -> Vec<Weekday> {
    use Weekday::*;
    vec![
        Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday,
    ]
}

fn deserialize_days<'de, D>(deserializer: D) -> Result<Vec<Weekday>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use Weekday::*;
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|day| {
            let day = day.to_ascii_lowercase();
            Ok(match day.get(..3).unwrap_or("") {
                "mon" if "monday".starts_with(&day) => Monday,
                "tue" if "tuesday".starts_with(&day) => Tuesday,
                "wed" if "wednesday".starts_with(&day) => Wednesday,
                "thu" if "thursday".starts_with(&day) => Thursday,
                "fri" if "friday".starts_with(&day) => Friday,
                "sat" if "saturday".starts_with(&day) => Saturday,
                "sun" if "sunday".starts_with(&day) => Sunday,
                _ => {
                    return Err(serde::de::Error::custom(format!(
                        "{day:?} is not a day of the week"
                    )));
                }
            })
        })
        .collect()
}

fn deserialize_time<'de, D>(deserializer: D) -> Result<Time, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    text.parse::<Time>()
        .map_err(|_| serde::de::Error::custom(format!("{text:?} is not a time like \"21:30\"")))
}

fn default_true() -> bool {
    true
}

/// Accepts plain addresses as single-host networks.
fn deserialize_nets<'de, D>(deserializer: D) -> Result<Vec<IpNet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer)?
        .iter()
        .map(|text| parse_net(text).map_err(serde::de::Error::custom))
        .collect()
}

fn parse_net(text: &str) -> Result<IpNet, String> {
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(IpNet::from(ip));
    }
    text.parse::<IpNet>()
        .map(|net| net.trunc())
        .map_err(|_| format!("{text:?} is not an IP address or network"))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    pub enabled: bool,
    /// Where the HTTP API listens. Keep it on loopback unless sign-in is set
    /// up with `users`, `tokens` or `token`.
    pub listen: SocketAddr,
    /// A single admin token, sent as `Authorization: Bearer <token>`. Kept
    /// for existing setups; `tokens` can be named, hashed and read-only.
    pub token: Option<String>,
    /// Web origins allowed to call the API from a browser, such as the
    /// dashboard's address (`http://localhost:8080`). Empty allows none.
    pub cors_origins: Vec<String>,
    /// Accounts that sign in to the dashboard with a name and password.
    pub users: Vec<UserConfig>,
    /// API tokens for scripts and other programs.
    pub tokens: Vec<TokenConfig>,
    /// A session from signing in ends after this long without a request...
    pub session_idle_secs: u64,
    /// ...and after this long in any case.
    pub session_max_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    pub name: String,
    /// Argon2id hash in PHC format, from `hushdns hash-password`.
    pub password_hash: String,
    #[serde(default)]
    pub role: Role,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    /// Shown in the audit log.
    pub name: String,
    /// SHA-256 of the token in hex, from `hushdns new-token`.
    pub hash: String,
    #[serde(default)]
    pub role: Role,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1:8053".parse().unwrap(),
            token: None,
            cors_origins: Vec::new(),
            users: Vec::new(),
            tokens: Vec::new(),
            session_idle_secs: 8 * 3600,
            session_max_secs: 7 * 86_400,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StatsConfig {
    /// Count queries per domain for the "top domains" lists. Kept in memory
    /// only; turn it off to keep no record of which names were looked up.
    pub top_domains: bool,
    /// Distinct domains tracked per list before new ones are ignored.
    pub max_tracked_domains: usize,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            top_domains: true,
            max_tracked_domains: 10_000,
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
        let mut config: Config = toml::from_str(text)?;
        anyhow::ensure!(!config.server.listen.is_empty(), "server.listen is empty");
        anyhow::ensure!(
            !config.upstream.servers.is_empty(),
            "upstream.servers is empty"
        );
        if config.tls.enabled() {
            anyhow::ensure!(
                config.tls.cert_file.is_some() && config.tls.key_file.is_some(),
                "tls.cert_file and tls.key_file are required to serve DoT or DoH"
            );
        }
        anyhow::ensure!(
            config.tls.doh_path.starts_with('/'),
            "tls.doh_path must start with /"
        );
        anyhow::ensure!(
            config.tls.reload_interval_secs > 0,
            "tls.reload_interval_secs must be positive"
        );
        let mut names = std::collections::HashSet::new();
        for client in &config.clients {
            anyhow::ensure!(!client.name.trim().is_empty(), "clients: name is empty");
            anyhow::ensure!(
                names.insert(client.name.as_str()),
                "clients: {:?} is listed twice",
                client.name
            );
            anyhow::ensure!(
                !client.addresses.is_empty(),
                "clients: {:?} has no addresses",
                client.name
            );
            for schedule in &client.schedules {
                anyhow::ensure!(
                    schedule.from != schedule.to,
                    "clients: {:?} has a schedule that starts and ends at the same time",
                    client.name
                );
                anyhow::ensure!(
                    schedule.block_all || !schedule.denylist.is_empty(),
                    "clients: {:?} has a schedule with nothing to block; set block_all or a denylist",
                    client.name
                );
                anyhow::ensure!(
                    !schedule.days.is_empty(),
                    "clients: {:?} has a schedule with no days",
                    client.name
                );
            }
        }
        if let Some(zone) = &config.server.timezone {
            jiff::tz::TimeZone::get(zone)
                .with_context(|| format!("server.timezone: {zone:?} is not a known time zone"))?;
        }
        config.api.check_credentials()?;
        for origin in &mut config.api.cors_origins {
            *origin = parse_origin(origin)
                .with_context(|| format!("api.cors_origins: {origin:?} is not a web origin"))?;
        }
        Ok(config)
    }
}

impl ApiConfig {
    fn check_credentials(&self) -> Result<()> {
        anyhow::ensure!(
            self.token.as_deref() != Some(""),
            "api.token is empty; remove it or set a value"
        );
        anyhow::ensure!(
            self.session_idle_secs > 0 && self.session_max_secs > 0,
            "api.session_idle_secs and api.session_max_secs must be positive"
        );
        let mut names = std::collections::HashSet::new();
        for user in &self.users {
            anyhow::ensure!(!user.name.trim().is_empty(), "api.users: name is empty");
            anyhow::ensure!(
                names.insert(user.name.as_str()),
                "api.users: {:?} is listed twice",
                user.name
            );
            auth::check_password_hash(&user.password_hash)
                .with_context(|| format!("api.users: {:?}", user.name))?;
        }
        let mut names = std::collections::HashSet::new();
        let mut hashes = std::collections::HashSet::new();
        for token in &self.tokens {
            anyhow::ensure!(!token.name.trim().is_empty(), "api.tokens: name is empty");
            anyhow::ensure!(
                names.insert(token.name.as_str()),
                "api.tokens: {:?} is listed twice",
                token.name
            );
            let hash = auth::parse_token_hash(&token.hash)
                .with_context(|| format!("api.tokens: {:?}", token.name))?;
            anyhow::ensure!(
                hashes.insert(hash),
                "api.tokens: {:?} has the same hash as another token",
                token.name
            );
        }
        Ok(())
    }
}

/// Normalizes a web origin such as `https://dash.example:8443`, rejecting
/// wildcards and anything with a path, query or credentials.
fn parse_origin(origin: &str) -> Result<String> {
    let url = url::Url::parse(origin)?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "scheme must be http or https"
    );
    anyhow::ensure!(
        url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none(),
        "expected only scheme, host and port"
    );
    Ok(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_listeners_need_a_certificate() {
        let err = Config::parse("[tls]\ndot_listen = [\"0.0.0.0:853\"]").unwrap_err();
        assert!(err.to_string().contains("cert_file"), "{err}");
        let config = Config::parse(
            r#"
            [tls]
            cert_file = "/etc/hushdns/tls/fullchain.pem"
            key_file = "/etc/hushdns/tls/privkey.pem"
            dot_listen = ["0.0.0.0:853"]
            doh_listen = ["0.0.0.0:443"]
            "#,
        )
        .unwrap();
        assert!(config.tls.enabled());
        assert_eq!(config.tls.doh_path, "/dns-query");
        assert!(Config::parse("[tls]\ndoh_path = \"dns-query\"").is_err());
    }

    #[test]
    fn sample_configs_parse() {
        for text in [
            include_str!("../config/hushdns.toml"),
            include_str!("../examples/compose/hushdns.toml"),
        ] {
            Config::parse(text).unwrap();
        }
    }

    #[test]
    fn normalizes_cors_origins() {
        let config = Config::parse(
            r#"
            [api]
            cors_origins = ["http://LOCALHOST:8080/", "https://dash.example:443"]
            "#,
        )
        .unwrap();
        assert_eq!(
            config.api.cors_origins,
            ["http://localhost:8080", "https://dash.example"]
        );
        for bad in ["*", "localhost:8080", "http://x.test/path", "ftp://x.test"] {
            let text = format!("[api]\ncors_origins = [{bad:?}]");
            assert!(Config::parse(&text).is_err(), "{bad}");
        }
    }

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
    fn parses_accounts_and_tokens() {
        let password_hash = auth::hash_password("pw").unwrap();
        let (_, token_hash) = auth::new_token();
        let text = format!(
            r#"
            [[api.users]]
            name = "ana"
            role = "admin"
            password_hash = "{password_hash}"

            [[api.users]]
            name = "bo"
            password_hash = "{password_hash}"

            [[api.tokens]]
            name = "home-assistant"
            hash = "{token_hash}"
            "#
        );
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.api.users[0].role, Role::Admin);
        assert_eq!(config.api.users[1].role, Role::Viewer);
        assert_eq!(config.api.tokens[0].role, Role::Viewer);

        let twice = text.replace("\"bo\"", "\"ana\"");
        assert!(Config::parse(&twice).is_err());
        let plain = text.replace(&password_hash, "hunter2");
        let err = Config::parse(&plain).unwrap_err();
        assert!(format!("{err:#}").contains("api.users: \"ana\""), "{err:#}");
        let short = text.replace(&token_hash, "abc");
        assert!(Config::parse(&short).is_err());
        assert!(Config::parse("[api]\nsession_idle_secs = 0").is_err());
        assert!(Config::parse("[api]\ntoken = \"\"").is_err());
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::parse("[server]\nlisen = []").is_err());
    }
}
