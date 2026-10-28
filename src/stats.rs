//! In-memory query counters. Nothing here is written to disk, and per-domain
//! counts can be turned off entirely.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;

use crate::config::StatsConfig;

/// How a query was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Blocked,
    Cached,
    Forwarded,
    /// Every upstream failed and the client got SERVFAIL.
    Failed,
    /// Malformed or unsupported query (FORMERR / NOTIMP).
    Invalid,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Blocked => "blocked",
            Outcome::Cached => "cached",
            Outcome::Forwarded => "forwarded",
            Outcome::Failed => "failed",
            Outcome::Invalid => "invalid",
        }
    }
}

/// Counts how often each domain was seen, up to a fixed number of domains so
/// a flood of random names cannot grow memory without bound.
struct DomainCounter {
    counts: Mutex<HashMap<Box<str>, u64>>,
    capacity: usize,
}

impl DomainCounter {
    fn new(capacity: usize) -> Self {
        Self {
            counts: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    fn record(&self, name: &str) {
        let mut counts = self.counts.lock().unwrap();
        if let Some(count) = counts.get_mut(name) {
            *count += 1;
        } else if counts.len() < self.capacity {
            counts.insert(name.into(), 1);
        }
    }

    fn top(&self, n: usize) -> Vec<DomainCount> {
        let counts = self.counts.lock().unwrap();
        let mut top: Vec<DomainCount> = counts
            .iter()
            .map(|(name, &count)| DomainCount {
                name: name.to_string(),
                count,
            })
            .collect();
        top.sort_unstable_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
        top.truncate(n);
        top
    }

    fn clear(&self) {
        self.counts.lock().unwrap().clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Counts {
    pub total: u64,
    pub blocked: u64,
    pub cached: u64,
    pub forwarded: u64,
    pub failed: u64,
    pub invalid: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub uptime_secs: u64,
    pub queries: Counts,
    /// Share of all queries that were blocked, from 0 to 1.
    pub blocked_ratio: f64,
    /// Empty when per-domain stats are turned off.
    pub top_queried: Vec<DomainCount>,
    pub top_blocked: Vec<DomainCount>,
}

pub struct Stats {
    started: Instant,
    blocked: AtomicU64,
    cached: AtomicU64,
    forwarded: AtomicU64,
    failed: AtomicU64,
    invalid: AtomicU64,
    domains: Option<(DomainCounter, DomainCounter)>,
}

impl Stats {
    pub fn new(config: &StatsConfig) -> Self {
        Self {
            started: Instant::now(),
            blocked: AtomicU64::new(0),
            cached: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            domains: config.top_domains.then(|| {
                (
                    DomainCounter::new(config.max_tracked_domains),
                    DomainCounter::new(config.max_tracked_domains),
                )
            }),
        }
    }

    /// Records one answered query. `name` is lower-case without the trailing dot.
    pub fn record(&self, name: Option<&str>, outcome: Outcome) {
        let counter = match outcome {
            Outcome::Blocked => &self.blocked,
            Outcome::Cached => &self.cached,
            Outcome::Forwarded => &self.forwarded,
            Outcome::Failed => &self.failed,
            Outcome::Invalid => &self.invalid,
        };
        counter.fetch_add(1, Ordering::Relaxed);

        if let (Some((queried, blocked)), Some(name)) = (&self.domains, name) {
            queried.record(name);
            if outcome == Outcome::Blocked {
                blocked.record(name);
            }
        }
    }

    pub fn snapshot(&self, top: usize) -> Snapshot {
        let mut queries = Counts {
            blocked: self.blocked.load(Ordering::Relaxed),
            cached: self.cached.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            invalid: self.invalid.load(Ordering::Relaxed),
            total: 0,
        };
        queries.total =
            queries.blocked + queries.cached + queries.forwarded + queries.failed + queries.invalid;
        let blocked_ratio = if queries.total == 0 {
            0.0
        } else {
            queries.blocked as f64 / queries.total as f64
        };
        let (top_queried, top_blocked) = match &self.domains {
            Some((queried, blocked)) => (queried.top(top), blocked.top(top)),
            None => (Vec::new(), Vec::new()),
        };
        Snapshot {
            uptime_secs: self.started.elapsed().as_secs(),
            queries,
            blocked_ratio,
            top_queried,
            top_blocked,
        }
    }

    /// Zeroes every counter.
    pub fn reset(&self) {
        for counter in [
            &self.blocked,
            &self.cached,
            &self.forwarded,
            &self.failed,
            &self.invalid,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
        if let Some((queried, blocked)) = &self.domains {
            queried.clear();
            blocked.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(top_domains: bool, max: usize) -> StatsConfig {
        StatsConfig {
            top_domains,
            max_tracked_domains: max,
        }
    }

    #[test]
    fn counts_outcomes_and_top_domains() {
        let stats = Stats::new(&config(true, 100));
        stats.record(Some("ads.example"), Outcome::Blocked);
        stats.record(Some("ads.example"), Outcome::Blocked);
        stats.record(Some("example.org"), Outcome::Forwarded);
        stats.record(Some("example.org"), Outcome::Cached);
        stats.record(Some("example.org"), Outcome::Cached);
        stats.record(None, Outcome::Invalid);

        let snap = stats.snapshot(10);
        assert_eq!(snap.queries.total, 6);
        assert_eq!(snap.queries.blocked, 2);
        assert_eq!(snap.queries.cached, 2);
        assert!((snap.blocked_ratio - 2.0 / 6.0).abs() < 1e-9);
        assert_eq!(
            snap.top_queried,
            vec![
                DomainCount {
                    name: "example.org".into(),
                    count: 3
                },
                DomainCount {
                    name: "ads.example".into(),
                    count: 2
                },
            ]
        );
        assert_eq!(snap.top_blocked.len(), 1);

        stats.reset();
        let snap = stats.snapshot(10);
        assert_eq!(snap.queries.total, 0);
        assert!(snap.top_queried.is_empty());
    }

    #[test]
    fn caps_tracked_domains() {
        let stats = Stats::new(&config(true, 2));
        for name in ["a.example", "b.example", "c.example", "a.example"] {
            stats.record(Some(name), Outcome::Forwarded);
        }
        let top = stats.snapshot(10).top_queried;
        assert_eq!(top.len(), 2);
        assert_eq!(
            top[0],
            DomainCount {
                name: "a.example".into(),
                count: 2
            }
        );
        assert_eq!(stats.snapshot(10).queries.total, 4);
    }

    #[test]
    fn domain_tracking_can_be_disabled() {
        let stats = Stats::new(&config(false, 100));
        stats.record(Some("example.org"), Outcome::Forwarded);
        let snap = stats.snapshot(10);
        assert_eq!(snap.queries.forwarded, 1);
        assert!(snap.top_queried.is_empty());
    }
}
