//! Per-client rules: groups of devices, matched by source address, that get
//! their own deny and allow lists, their own blocklists and schedules, or
//! skip the shared blocklists.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use ipnet::IpNet;
use jiff::civil::{DateTime, Time, Weekday};
use jiff::tz::TimeZone;
use serde::Serialize;

use crate::blocklist::{Blocklist, DomainSet, Rules, SourceStatus, Verdict};
use crate::config::{ClientConfig, ScheduleConfig};

/// The rule reported for names a `block_all` schedule blocks.
pub const BLOCK_ALL_RULE: &str = "*";

/// One `[[clients]]` group with its compiled rules.
#[derive(Debug)]
pub struct Client {
    pub name: String,
    nets: Vec<IpNet>,
    blocklists: bool,
    denied: DomainSet,
    allowed: DomainSet,
    lists: Vec<String>,
    list_rules: ArcSwap<Rules>,
    sources: ArcSwap<Vec<SourceStatus>>,
    schedules: Vec<Schedule>,
    paused_until: Mutex<Option<Instant>>,
}

#[derive(Debug)]
struct Schedule {
    days: Vec<Weekday>,
    from: Time,
    to: Time,
    block_all: bool,
    denied: DomainSet,
}

impl Schedule {
    fn new(config: &ScheduleConfig) -> Self {
        let mut denied = DomainSet::default();
        config.denylist.iter().for_each(|d| denied.insert(d));
        Self {
            days: config.days.clone(),
            from: config.from,
            to: config.to,
            block_all: config.block_all,
            denied,
        }
    }

    /// Whether `now` falls in the window. A window that ends before it starts
    /// runs past midnight, and belongs to the day it starts on.
    fn active_at(&self, now: DateTime) -> bool {
        let (day, time) = (now.weekday(), now.time());
        if self.from < self.to {
            self.days.contains(&day) && self.from <= time && time < self.to
        } else {
            (self.days.contains(&day) && time >= self.from)
                || (self.days.contains(&day.previous()) && time < self.to)
        }
    }
}

impl Client {
    fn new(config: &ClientConfig) -> Self {
        let mut denied = DomainSet::default();
        config.denylist.iter().for_each(|d| denied.insert(d));
        let mut allowed = DomainSet::default();
        config.allowlist.iter().for_each(|d| allowed.insert(d));
        Self {
            name: config.name.clone(),
            nets: config.addresses.clone(),
            blocklists: config.blocklists,
            denied,
            allowed,
            lists: config.lists.clone(),
            list_rules: ArcSwap::default(),
            sources: ArcSwap::default(),
            schedules: config.schedules.iter().map(Schedule::new).collect(),
            paused_until: Mutex::new(None),
        }
    }

    /// Turns this group's own rules off for `duration`, so its clients get
    /// only the shared rules. A zero duration resumes them now.
    pub fn pause(&self, duration: Duration) {
        *self.paused_until.lock().unwrap() =
            (!duration.is_zero()).then(|| Instant::now() + duration);
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

    /// What the dashboard and API show about this group.
    pub fn status(&self, now: DateTime) -> ClientStatus {
        let list_rules = self.list_rules.load();
        ClientStatus {
            name: self.name.clone(),
            addresses: self
                .nets
                .iter()
                .map(|net| match net.prefix_len() == net.max_prefix_len() {
                    true => net.addr().to_string(),
                    false => net.to_string(),
                })
                .collect(),
            blocklists: self.blocklists,
            denylist: self.denied.len(),
            allowlist: self.allowed.len(),
            list_domains: list_rules.blocked.len(),
            sources: self.sources.load().to_vec(),
            schedules: self
                .schedules
                .iter()
                .map(|s| ScheduleStatus {
                    days: s.days.iter().map(|d| day_name(*d)).collect(),
                    from: s.from.strftime("%H:%M").to_string(),
                    to: s.to.strftime("%H:%M").to_string(),
                    block_all: s.block_all,
                    denylist: s.denied.len(),
                    active: s.active_at(now),
                })
                .collect(),
            paused_for_secs: self.paused_for().map(|d| d.as_secs()),
        }
    }
}

fn day_name(day: Weekday) -> &'static str {
    match day {
        Weekday::Monday => "mon",
        Weekday::Tuesday => "tue",
        Weekday::Wednesday => "wed",
        Weekday::Thursday => "thu",
        Weekday::Friday => "fri",
        Weekday::Saturday => "sat",
        Weekday::Sunday => "sun",
    }
}

#[derive(Debug, Serialize)]
pub struct ClientStatus {
    pub name: String,
    pub addresses: Vec<String>,
    /// Whether the shared lists apply to this group.
    pub blocklists: bool,
    pub denylist: usize,
    pub allowlist: usize,
    /// Domains blocked by this group's own lists.
    pub list_domains: usize,
    pub sources: Vec<SourceStatus>,
    pub schedules: Vec<ScheduleStatus>,
    /// Seconds left while this group's own rules are paused.
    pub paused_for_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ScheduleStatus {
    pub days: Vec<&'static str>,
    pub from: String,
    pub to: String,
    pub block_all: bool,
    pub denylist: usize,
    /// Whether the window is open right now.
    pub active: bool,
}

/// Every configured client group, and the time zone their schedules use.
#[derive(Debug)]
pub struct Clients {
    groups: Vec<Client>,
    timezone: TimeZone,
}

impl Default for Clients {
    fn default() -> Self {
        Self {
            groups: Vec::new(),
            timezone: TimeZone::UTC,
        }
    }
}

impl Clients {
    /// Builds the groups. `timezone` is an IANA name, or `None` for the
    /// system's zone.
    pub fn new(config: &[ClientConfig], timezone: Option<&str>) -> anyhow::Result<Self> {
        let timezone = match timezone {
            Some(name) => TimeZone::get(name)?,
            None => TimeZone::system(),
        };
        Ok(Self {
            groups: config.iter().map(Client::new).collect(),
            timezone,
        })
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn groups(&self) -> &[Client] {
        &self.groups
    }

    pub fn get(&self, name: &str) -> Option<&Client> {
        self.groups.iter().find(|g| g.name == name)
    }

    /// The current wall-clock time in the schedules' time zone.
    pub fn now(&self) -> DateTime {
        jiff::Timestamp::now()
            .to_zoned(self.timezone.clone())
            .datetime()
    }

    /// The group `ip` belongs to. The most specific network wins, and among
    /// equally specific ones the group listed first.
    pub fn lookup(&self, ip: IpAddr) -> Option<&Client> {
        // Dual-stack sockets report IPv4 clients as ::ffff:a.b.c.d.
        let ip = ip.to_canonical();
        let mut best: Option<(&Client, u8)> = None;
        for group in &self.groups {
            for net in group.nets.iter().filter(|net| net.contains(&ip)) {
                if best.is_none_or(|(_, len)| net.prefix_len() > len) {
                    best = Some((group, net.prefix_len()));
                }
            }
        }
        best.map(|(group, _)| group)
    }

    /// Downloads every group's own lists. Called from [`Blocklist::reload`].
    pub(crate) async fn reload(&self, blocklist: &Blocklist) {
        for group in self.groups.iter().filter(|g| !g.lists.is_empty()) {
            let mut rules = Rules::default();
            let sources = blocklist.load_sources(&group.lists, &mut rules).await;
            group.list_rules.store(Arc::new(rules));
            group.sources.store(Arc::new(sources));
        }
    }
}

/// Decides whether `name` is blocked for `client` at `now`, and returns the
/// matching rule if so. A client's allowlist wins over everything. Then come
/// its open schedules, its denylist, its own lists, and last the shared rules
/// unless it skips them. A paused group gets only the shared rules.
pub fn check<'a>(
    rules: &'a Rules,
    client: Option<&'a Client>,
    name: &str,
    now: DateTime,
) -> Option<Cow<'a, str>> {
    let shared = || match rules.check(name) {
        Verdict::Blocked(rule) => Some(Cow::Borrowed(rule)),
        Verdict::Allowed => None,
    };
    let Some(client) = client.filter(|c| c.paused_for().is_none()) else {
        return shared();
    };
    if client.allowed.matches(name).is_some() {
        return None;
    }
    for schedule in client.schedules.iter().filter(|s| s.active_at(now)) {
        if schedule.block_all {
            return Some(Cow::Borrowed(BLOCK_ALL_RULE));
        }
        if let Some(rule) = schedule.denied.matches(name) {
            return Some(Cow::Borrowed(rule));
        }
    }
    if let Some(rule) = client.denied.matches(name) {
        return Some(Cow::Borrowed(rule));
    }
    let list_rules = client.list_rules.load();
    if let Verdict::Blocked(rule) = list_rules.check(name) {
        // The lists can be swapped by a reload, so the rule is copied out.
        return Some(Cow::Owned(rule.to_string()));
    }
    if client.blocklists { shared() } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn clients(toml: &str) -> Clients {
        Clients::new(&Config::parse(toml).unwrap().clients, Some("UTC")).unwrap()
    }

    /// 2026-10-26 is a Monday.
    fn at(text: &str) -> DateTime {
        text.parse().unwrap()
    }

    const MONDAY_NOON: &str = "2026-10-26T12:00";

    #[test]
    fn most_specific_network_wins() {
        let clients = clients(
            r#"
            [[clients]]
            name = "lan"
            addresses = ["192.168.1.0/24", "fd00::/8"]
            [[clients]]
            name = "tablet"
            addresses = ["192.168.1.20"]
            [[clients]]
            name = "also-lan"
            addresses = ["192.168.1.7/24"]
            "#,
        );
        let name = |ip: &str| clients.lookup(ip.parse().unwrap()).map(|c| c.name.as_str());
        assert_eq!(name("192.168.1.20"), Some("tablet"));
        assert_eq!(name("::ffff:192.168.1.20"), Some("tablet"));
        // Equal prefixes: the group listed first.
        assert_eq!(name("192.168.1.21"), Some("lan"));
        assert_eq!(name("fd12::1"), Some("lan"));
        assert_eq!(name("10.0.0.1"), None);
    }

    #[test]
    fn client_rules_come_before_shared_rules() {
        let mut shared = Rules::default();
        shared.blocked.insert("ads.example.com");
        shared.blocked.insert("social.example");
        shared.allowed.insert("video.example");
        let clients = clients(
            r#"
            [[clients]]
            name = "kids"
            addresses = ["10.0.0.0/24"]
            denylist = ["video.example"]
            allowlist = ["social.example"]
            [[clients]]
            name = "work"
            addresses = ["10.0.1.0/24"]
            blocklists = false
            denylist = ["games.example"]
            "#,
        );
        let kids = clients.lookup("10.0.0.5".parse().unwrap());
        let work = clients.lookup("10.0.1.5".parse().unwrap());
        let now = at(MONDAY_NOON);
        let check = |client, name| check(&shared, client, name, now).map(Cow::into_owned);

        assert_eq!(
            check(kids, "www.video.example").as_deref(),
            Some("video.example")
        );
        assert_eq!(check(kids, "social.example"), None);
        assert_eq!(
            check(kids, "ads.example.com").as_deref(),
            Some("ads.example.com")
        );

        assert_eq!(check(work, "ads.example.com"), None);
        assert_eq!(
            check(work, "games.example").as_deref(),
            Some("games.example")
        );

        assert_eq!(
            check(None, "social.example").as_deref(),
            Some("social.example")
        );
    }

    #[test]
    fn schedules_open_on_their_days_and_run_past_midnight() {
        let clients = clients(
            r#"
            [[clients]]
            name = "kids"
            addresses = ["10.0.0.0/24"]
            allowlist = ["school.example"]
            [[clients.schedules]]
            days = ["sun", "mon", "tue", "wed", "thu"]
            from = "21:00"
            to = "07:00"
            block_all = true
            [[clients.schedules]]
            days = ["Saturday"]
            from = "10:00"
            to = "12:30"
            denylist = ["games.example"]
            "#,
        );
        let shared = Rules::default();
        let kids = clients.lookup("10.0.0.5".parse().unwrap());
        let blocked = |name, when| check(&shared, kids, name, at(when)).is_some();

        // Monday night into Tuesday morning.
        assert!(blocked("example.org", "2026-10-26T21:00"));
        assert!(blocked("example.org", "2026-10-27T06:59"));
        assert!(!blocked("example.org", "2026-10-27T07:00"));
        assert!(!blocked("example.org", "2026-10-26T20:59"));
        // The allowlist still wins at night.
        assert!(!blocked("school.example", "2026-10-26T23:00"));
        // Friday night is not listed, but Thursday night runs into Friday.
        assert!(blocked("example.org", "2026-10-30T06:00"));
        assert!(!blocked("example.org", "2026-10-30T22:00"));
        assert!(!blocked("example.org", "2026-10-31T06:00"));
        // Saturday's window blocks only its denylist.
        assert!(blocked("www.games.example", "2026-10-31T11:00"));
        assert!(!blocked("example.org", "2026-10-31T11:00"));
        assert!(!blocked("www.games.example", "2026-10-31T12:30"));
    }

    #[test]
    fn a_paused_group_gets_only_the_shared_rules() {
        let mut shared = Rules::default();
        shared.blocked.insert("ads.example.com");
        let clients = clients(
            r#"
            [[clients]]
            name = "kids"
            addresses = ["10.0.0.0/24"]
            blocklists = false
            denylist = ["video.example"]
            "#,
        );
        let kids = clients.get("kids");
        let now = at(MONDAY_NOON);
        assert!(check(&shared, kids, "video.example", now).is_some());
        assert!(check(&shared, kids, "ads.example.com", now).is_none());

        kids.unwrap().pause(Duration::from_secs(60));
        assert!(kids.unwrap().paused_for().is_some());
        assert!(check(&shared, kids, "video.example", now).is_none());
        assert!(check(&shared, kids, "ads.example.com", now).is_some());

        kids.unwrap().pause(Duration::ZERO);
        assert!(check(&shared, kids, "video.example", now).is_some());
    }

    #[tokio::test]
    async fn loads_each_groups_own_lists() {
        let dir = std::env::temp_dir().join(format!("dns-client-lists-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let list = dir.join("social.txt");
        std::fs::write(&list, "||social.example^\n@@||ok.social.example^\n").unwrap();
        let config = Config::parse(&format!(
            r#"
            [[clients]]
            name = "kids"
            addresses = ["10.0.0.0/24"]
            lists = [{list:?}, "/nonexistent/list.txt"]
            "#
        ))
        .unwrap();
        let clients = Arc::new(Clients::new(&config.clients, Some("UTC")).unwrap());
        let blocklist = Blocklist::new(config.blocking.clone())
            .unwrap()
            .with_clients(Arc::clone(&clients));
        blocklist.reload().await;

        let kids = clients.get("kids");
        let rules = blocklist.rules();
        let now = at(MONDAY_NOON);
        assert_eq!(
            check(&rules, kids, "www.social.example", now).as_deref(),
            Some("social.example")
        );
        assert!(check(&rules, kids, "ok.social.example", now).is_none());
        assert!(check(&rules, None, "www.social.example", now).is_none());

        let status = kids.unwrap().status(now);
        assert_eq!(status.list_domains, 1);
        assert_eq!(status.sources[0].domains, 1);
        assert!(status.sources[1].error.is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_bad_groups() {
        for (toml, expected) in [
            (
                "[[clients]]\nname = \"a\"\naddresses = [\"nope\"]",
                "not an IP",
            ),
            ("[[clients]]\nname = \"a\"\naddresses = []", "no addresses"),
            (
                "[[clients]]\nname = \"\"\naddresses = [\"10.0.0.1\"]",
                "name is empty",
            ),
            (
                "[[clients]]\nname = \"a\"\naddresses = [\"10.0.0.1\"]\n[[clients]]\nname = \"a\"\naddresses = [\"10.0.0.2\"]",
                "listed twice",
            ),
            (
                "[[clients]]\nname = \"a\"\naddresses = [\"10.0.0.1\"]\n[[clients.schedules]]\nfrom = \"21:00\"\nto = \"07:00\"",
                "nothing to block",
            ),
            (
                "[[clients]]\nname = \"a\"\naddresses = [\"10.0.0.1\"]\n[[clients.schedules]]\ndays = [\"funday\"]\nfrom = \"21:00\"\nto = \"07:00\"\nblock_all = true",
                "not a day",
            ),
            (
                "[[clients]]\nname = \"a\"\naddresses = [\"10.0.0.1\"]\n[[clients.schedules]]\nfrom = \"9pm\"\nto = \"07:00\"\nblock_all = true",
                "not a time",
            ),
            (
                "[server]\ntimezone = \"Mars/Olympus\"",
                "not a known time zone",
            ),
        ] {
            let err = format!("{:#}", Config::parse(toml).unwrap_err());
            assert!(err.contains(expected), "{toml}: {err}");
        }
    }
}
