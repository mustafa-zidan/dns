//! Per-client rules: groups of devices, matched by source address, that get
//! their own deny and allow lists or skip the shared blocklists.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::blocklist::{DomainSet, Rules, Verdict};
use crate::config::ClientConfig;

/// One `[[clients]]` group with its compiled rules.
#[derive(Debug)]
pub struct Client {
    pub name: String,
    nets: Vec<IpNet>,
    blocklists: bool,
    denied: DomainSet,
    allowed: DomainSet,
}

/// Every configured client group.
#[derive(Debug, Default)]
pub struct Clients {
    groups: Vec<Client>,
}

impl Clients {
    pub fn new(config: &[ClientConfig]) -> Self {
        let groups = config
            .iter()
            .map(|c| {
                let mut denied = DomainSet::default();
                c.denylist.iter().for_each(|d| denied.insert(d));
                let mut allowed = DomainSet::default();
                c.allowlist.iter().for_each(|d| allowed.insert(d));
                Client {
                    name: c.name.clone(),
                    nets: c.addresses.clone(),
                    blocklists: c.blocklists,
                    denied,
                    allowed,
                }
            })
            .collect();
        Self { groups }
    }

    pub fn len(&self) -> usize {
        self.groups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
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
}

/// Decides whether `name` is blocked for `client`: the client's allowlist,
/// then its denylist, then the shared rules unless the client skips them.
pub fn check<'a>(rules: &'a Rules, client: Option<&'a Client>, name: &str) -> Verdict<'a> {
    let Some(client) = client else {
        return rules.check(name);
    };
    if client.allowed.matches(name).is_some() {
        return Verdict::Allowed;
    }
    if let Some(rule) = client.denied.matches(name) {
        return Verdict::Blocked(rule);
    }
    if client.blocklists {
        rules.check(name)
    } else {
        Verdict::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn clients(toml: &str) -> Clients {
        Clients::new(&Config::parse(toml).unwrap().clients)
    }

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

        assert_eq!(
            check(&shared, kids, "www.video.example"),
            Verdict::Blocked("video.example")
        );
        assert_eq!(check(&shared, kids, "social.example"), Verdict::Allowed);
        assert_eq!(
            check(&shared, kids, "ads.example.com"),
            Verdict::Blocked("ads.example.com")
        );

        assert_eq!(check(&shared, work, "ads.example.com"), Verdict::Allowed);
        assert_eq!(
            check(&shared, work, "games.example"),
            Verdict::Blocked("games.example")
        );

        assert_eq!(
            check(&shared, None, "social.example"),
            Verdict::Blocked("social.example")
        );
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
        ] {
            let err = format!("{:#}", Config::parse(toml).unwrap_err());
            assert!(err.contains(expected), "{toml}: {err}");
        }
    }
}
