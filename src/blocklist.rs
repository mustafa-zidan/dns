use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use serde::Serialize;
use tracing::{info, warn};

use crate::clients::{self, Clients};
use crate::config::BlockingConfig;

/// A set of domains where an entry also matches all of its subdomains.
#[derive(Debug, Default)]
pub struct DomainSet {
    domains: HashSet<Box<str>>,
}

impl DomainSet {
    pub fn insert(&mut self, domain: &str) {
        if let Some(domain) = normalize(domain) {
            self.domains.insert(domain.into_boxed_str());
        }
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Returns the entry matching `name` or one of its parent domains.
    pub fn matches(&self, name: &str) -> Option<&str> {
        let mut candidate = name;
        loop {
            if let Some(hit) = self.domains.get(candidate) {
                return Some(hit);
            }
            match candidate.split_once('.') {
                Some((_, parent)) if !parent.is_empty() => candidate = parent,
                _ => return None,
            }
        }
    }
}

/// Lower-cases a domain, strips the trailing dot and checks it looks like a hostname.
fn normalize(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63)
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    valid.then_some(domain)
}

/// The decision for a queried name.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict<'a> {
    Allowed,
    /// Blocked by the given rule.
    Blocked(&'a str),
}

/// The compiled block and allow rules.
#[derive(Debug, Default)]
pub struct Rules {
    pub blocked: DomainSet,
    pub allowed: DomainSet,
}

impl Rules {
    /// Decides whether `name` (lower-case, no trailing dot) is blocked.
    pub fn check(&self, name: &str) -> Verdict<'_> {
        if self.allowed.matches(name).is_some() {
            return Verdict::Allowed;
        }
        match self.blocked.matches(name) {
            Some(rule) => Verdict::Blocked(rule),
            None => Verdict::Allowed,
        }
    }

    /// Adds every rule found in a list's text. Lines may be hosts-file
    /// entries, bare domains, or adblock-style `||domain^` / `@@||domain^` rules.
    pub fn add_list(&mut self, text: &str) {
        for line in text.lines() {
            match parse_line(line) {
                Some(Rule::Block(domains)) => {
                    domains.into_iter().for_each(|d| self.blocked.insert(d))
                }
                Some(Rule::Allow(domain)) => self.allowed.insert(domain),
                None => {}
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Rule<'a> {
    Block(Vec<&'a str>),
    Allow(&'a str),
}

const HOSTS_IGNORED: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
];

fn parse_line(line: &str) -> Option<Rule<'_>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') || line.starts_with('[') {
        return None;
    }

    if let Some(rest) = line.strip_prefix("@@||") {
        return adblock_domain(rest).map(Rule::Allow);
    }
    if let Some(rest) = line.strip_prefix("||") {
        return adblock_domain(rest).map(|d| Rule::Block(vec![d]));
    }

    let line = line.split('#').next().unwrap_or_default();
    let mut tokens = line.split_whitespace();
    let first = tokens.next()?;
    if first.parse::<std::net::IpAddr>().is_ok() {
        // hosts file: "0.0.0.0 ads.example.com tracker.example.com"
        let domains: Vec<&str> = tokens.filter(|d| !HOSTS_IGNORED.contains(d)).collect();
        return (!domains.is_empty()).then_some(Rule::Block(domains));
    }
    if tokens.next().is_none() && !first.contains(['/', '*', '$', '^']) {
        return Some(Rule::Block(vec![first]));
    }
    None
}

/// Extracts the domain from the part of an adblock rule after `||`.
/// Only plain domain rules apply to DNS; anything with a path, wildcard or
/// modifiers other than `$important` is skipped.
fn adblock_domain(rest: &str) -> Option<&str> {
    let (rule, modifiers) = match rest.split_once('$') {
        Some((rule, modifiers)) => (rule, Some(modifiers)),
        None => (rest, None),
    };
    if modifiers.is_some_and(|m| m != "important") {
        return None;
    }
    let domain = rule.strip_suffix('^').unwrap_or(rule);
    (!domain.is_empty() && !domain.contains(['/', '*', '^', '|'])).then_some(domain)
}

/// The outcome of loading one blocklist source.
#[derive(Debug, Clone, Serialize)]
pub struct SourceStatus {
    pub source: String,
    /// Domains this source added that no earlier source already had.
    pub domains: usize,
    pub error: Option<String>,
}

/// Holds the active rules and swaps them atomically when lists are reloaded.
/// Blocking can also be switched off, or paused for a while, at runtime.
pub struct Blocklist {
    rules: ArcSwap<Rules>,
    sources: ArcSwap<Vec<SourceStatus>>,
    last_reload: Mutex<Option<SystemTime>>,
    reloading: tokio::sync::Mutex<()>,
    enabled: AtomicBool,
    paused_until: Mutex<Option<Instant>>,
    config: BlockingConfig,
    clients: Arc<Clients>,
    http: reqwest::Client,
}

impl Blocklist {
    pub fn new(config: BlockingConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("dns/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let blocklist = Self {
            rules: ArcSwap::default(),
            sources: ArcSwap::default(),
            last_reload: Mutex::new(None),
            reloading: tokio::sync::Mutex::new(()),
            enabled: AtomicBool::new(config.enabled),
            paused_until: Mutex::new(None),
            config,
            clients: Arc::default(),
            http,
        };
        // Start with the inline rules so blocking works before any download finishes.
        blocklist.rules.store(Arc::new(blocklist.inline_rules()));
        Ok(blocklist)
    }

    /// Per-client groups, whose own lists load and refresh with the shared ones.
    pub fn with_clients(mut self, clients: Arc<Clients>) -> Self {
        self.clients = clients;
        self
    }

    pub fn clients(&self) -> &Clients {
        &self.clients
    }

    /// The rule blocking `name` for a query from `client`, if any. Applies
    /// the client's group, when it has one, on top of the shared rules.
    pub fn blocked_by(&self, name: &str, client: Option<IpAddr>) -> Option<(String, Option<&str>)> {
        let group = client.and_then(|ip| self.clients.lookup(ip));
        let rules = self.rules();
        let rule = match group {
            Some(group) => clients::check(&rules, Some(group), name, self.clients.now()),
            None => match rules.check(name) {
                Verdict::Blocked(rule) => Some(rule.into()),
                Verdict::Allowed => None,
            },
        }?;
        Some((rule.into_owned(), group.map(|g| g.name.as_str())))
    }

    /// Whether queries are being checked against the rules right now.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed) && self.paused_for().is_none()
    }

    /// Switches blocking on or off, cancelling any pause.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        *self.paused_until.lock().unwrap() = None;
    }

    /// Stops blocking for `duration`, after which it resumes on its own.
    pub fn pause(&self, duration: Duration) {
        self.enabled.store(true, Ordering::Relaxed);
        *self.paused_until.lock().unwrap() = Some(Instant::now() + duration);
    }

    /// Time left on the current pause, if any.
    pub fn paused_for(&self) -> Option<Duration> {
        let mut paused = self.paused_until.lock().unwrap();
        let remaining = paused.and_then(|until| until.checked_duration_since(Instant::now()));
        if remaining.is_none() {
            *paused = None;
        }
        remaining
    }

    pub fn rules(&self) -> arc_swap::Guard<Arc<Rules>> {
        self.rules.load()
    }

    /// How each source fared on the last reload.
    pub fn sources(&self) -> Arc<Vec<SourceStatus>> {
        self.sources.load_full()
    }

    pub fn last_reload(&self) -> Option<SystemTime> {
        *self.last_reload.lock().unwrap()
    }

    fn inline_rules(&self) -> Rules {
        let mut rules = Rules::default();
        self.config
            .denylist
            .iter()
            .for_each(|d| rules.blocked.insert(d));
        self.config
            .allowlist
            .iter()
            .for_each(|d| rules.allowed.insert(d));
        rules
    }

    /// Fetches every configured source and replaces the active rules. A source
    /// that fails to load is skipped, so one bad URL does not disable blocking.
    pub async fn reload(&self) {
        // Overlapping reloads (timer and API) would only repeat the downloads.
        let _guard = self.reloading.lock().await;
        let mut rules = self.inline_rules();
        let sources = self.load_sources(&self.config.lists, &mut rules).await;
        info!(
            blocked = rules.blocked.len(),
            allowed = rules.allowed.len(),
            "blocklists ready"
        );
        self.rules.store(Arc::new(rules));
        self.sources.store(Arc::new(sources));
        self.clients.reload(self).await;
        *self.last_reload.lock().unwrap() = Some(SystemTime::now());
    }

    /// Adds every source's rules to `rules`. A source that fails to load is
    /// reported and skipped.
    pub(crate) async fn load_sources(
        &self,
        lists: &[String],
        rules: &mut Rules,
    ) -> Vec<SourceStatus> {
        let mut sources = Vec::with_capacity(lists.len());
        for source in lists {
            match self.fetch(source).await {
                Ok(text) => {
                    let before = rules.blocked.len();
                    rules.add_list(&text);
                    let added = rules.blocked.len() - before;
                    info!(source, added, "loaded blocklist");
                    sources.push(SourceStatus {
                        source: source.clone(),
                        domains: added,
                        error: None,
                    });
                }
                Err(e) => {
                    let error = format!("{e:#}");
                    warn!(source, error, "failed to load blocklist");
                    sources.push(SourceStatus {
                        source: source.clone(),
                        domains: 0,
                        error: Some(error),
                    });
                }
            }
        }
        sources
    }

    async fn fetch(&self, source: &str) -> Result<String> {
        if source.starts_with("http://") || source.starts_with("https://") {
            let response = self.http.get(source).send().await?;
            if !response.status().is_success() {
                bail!("HTTP {}", response.status());
            }
            Ok(response.text().await?)
        } else {
            let path = source.strip_prefix("file://").unwrap_or(source);
            tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("reading {path}"))
        }
    }

    /// Loads the lists now, then keeps refreshing them on the configured interval.
    pub fn spawn_refresh(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.reload().await;
            if this.config.refresh_interval_secs == 0 {
                return;
            }
            let period = Duration::from_secs(this.config.refresh_interval_secs);
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            loop {
                interval.tick().await;
                this.reload().await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_list_formats() {
        let cases = [
            (
                "0.0.0.0 ads.example.com",
                Some(Rule::Block(vec!["ads.example.com"])),
            ),
            (
                "127.0.0.1 a.com b.com # trailing",
                Some(Rule::Block(vec!["a.com", "b.com"])),
            ),
            ("127.0.0.1 localhost", None),
            (
                ":: ads.example.com",
                Some(Rule::Block(vec!["ads.example.com"])),
            ),
            (
                "tracker.example.net",
                Some(Rule::Block(vec!["tracker.example.net"])),
            ),
            (
                "||ads.example.org^",
                Some(Rule::Block(vec!["ads.example.org"])),
            ),
            (
                "||ads.example.org^$important",
                Some(Rule::Block(vec!["ads.example.org"])),
            ),
            (
                "@@||good.example.org^",
                Some(Rule::Allow("good.example.org")),
            ),
            ("||ads.example.org^$third-party", None),
            ("||example.org/path", None),
            ("||*.example.org^", None),
            ("# comment", None),
            ("! adblock comment", None),
            ("[Adblock Plus 2.0]", None),
            ("", None),
        ];
        for (line, expected) in cases {
            assert_eq!(parse_line(line), expected, "line {line:?}");
        }
    }

    #[test]
    fn blocks_subdomains_and_honours_allowlist() {
        let mut rules = Rules::default();
        rules.add_list("0.0.0.0 ads.example.com\n||tracker.net^\n@@||ok.tracker.net^\n");
        assert_eq!(
            rules.check("ads.example.com"),
            Verdict::Blocked("ads.example.com")
        );
        assert_eq!(
            rules.check("x.y.ads.example.com"),
            Verdict::Blocked("ads.example.com")
        );
        assert_eq!(rules.check("example.com"), Verdict::Allowed);
        assert_eq!(
            rules.check("cdn.tracker.net"),
            Verdict::Blocked("tracker.net")
        );
        assert_eq!(rules.check("ok.tracker.net"), Verdict::Allowed);
        assert_eq!(rules.check("a.ok.tracker.net"), Verdict::Allowed);
    }

    #[test]
    fn normalizes_entries() {
        let mut set = DomainSet::default();
        set.insert("Ads.Example.COM.");
        set.insert("not a domain");
        set.insert("nodot");
        assert_eq!(set.len(), 1);
        assert!(set.matches("ads.example.com").is_some());
    }

    #[test]
    fn pauses_and_toggles_blocking() {
        let blocklist = Blocklist::new(BlockingConfig::default()).unwrap();
        assert!(blocklist.enabled());
        blocklist.set_enabled(false);
        assert!(!blocklist.enabled());
        blocklist.pause(Duration::from_secs(60));
        assert!(!blocklist.enabled());
        assert!(blocklist.paused_for().unwrap() > Duration::from_secs(50));
        blocklist.pause(Duration::ZERO);
        assert!(blocklist.enabled());
        assert!(blocklist.paused_for().is_none());
    }

    #[tokio::test]
    async fn loads_lists_from_files() {
        let dir = std::env::temp_dir().join(format!("dns-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts.txt");
        std::fs::write(&path, "0.0.0.0 ads.example.com\n").unwrap();

        let blocklist = Blocklist::new(BlockingConfig {
            lists: vec![
                path.to_string_lossy().into_owned(),
                "/does/not/exist".into(),
            ],
            denylist: vec!["inline.example".into()],
            ..BlockingConfig::default()
        })
        .unwrap();
        assert_eq!(blocklist.rules().blocked.len(), 1);
        blocklist.reload().await;
        assert_eq!(blocklist.rules().blocked.len(), 2);
        let sources = blocklist.sources();
        assert_eq!(sources[0].domains, 1);
        assert!(sources[1].error.is_some());
        assert!(blocklist.last_reload().is_some());
        assert!(matches!(
            blocklist.rules().check("ads.example.com"),
            Verdict::Blocked(_)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
