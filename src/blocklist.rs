use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use tracing::{info, warn};

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

/// Holds the active rules and swaps them atomically when lists are reloaded.
pub struct Blocklist {
    rules: ArcSwap<Rules>,
    config: BlockingConfig,
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
            config,
            http,
        };
        // Start with the inline rules so blocking works before any download finishes.
        blocklist.rules.store(Arc::new(blocklist.inline_rules()));
        Ok(blocklist)
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn rules(&self) -> arc_swap::Guard<Arc<Rules>> {
        self.rules.load()
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
        let mut rules = self.inline_rules();
        for source in &self.config.lists {
            match self.fetch(source).await {
                Ok(text) => {
                    let before = rules.blocked.len();
                    rules.add_list(&text);
                    info!(
                        source,
                        added = rules.blocked.len() - before,
                        "loaded blocklist"
                    );
                }
                Err(e) => warn!(source, error = %format!("{e:#}"), "failed to load blocklist"),
            }
        }
        info!(
            blocked = rules.blocked.len(),
            allowed = rules.allowed.len(),
            "blocklists ready"
        );
        self.rules.store(Arc::new(rules));
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
        assert!(matches!(
            blocklist.rules().check("ads.example.com"),
            Verdict::Blocked(_)
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
