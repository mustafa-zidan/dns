//! Counts failed sign-ins, and refuses more once there are too many.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Allows `max_failures` failed attempts per key in each fixed window.
pub struct Limiter<K> {
    max_failures: u32,
    window: Duration,
    /// Keys tracked at most. Past it, finished windows are dropped first,
    /// then the oldest.
    capacity: usize,
    windows: Mutex<HashMap<K, Window>>,
}

struct Window {
    started: Instant,
    failures: u32,
}

impl<K: Hash + Eq + Clone> Limiter<K> {
    pub fn new(max_failures: u32, window: Duration, capacity: usize) -> Self {
        Self {
            max_failures,
            window,
            capacity,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// How long until `key` may try again, if it has used up its attempts.
    pub fn retry_after(&self, key: &K, now: Instant) -> Option<Duration> {
        let windows = self.windows.lock().unwrap();
        let window = windows.get(key)?;
        let left = self
            .window
            .checked_sub(now.saturating_duration_since(window.started))?;
        (window.failures >= self.max_failures && !left.is_zero()).then_some(left)
    }

    pub fn fail(&self, key: K, now: Instant) {
        let mut windows = self.windows.lock().unwrap();
        if windows.len() >= self.capacity && !windows.contains_key(&key) {
            windows.retain(|_, w| now.saturating_duration_since(w.started) < self.window);
            if windows.len() >= self.capacity {
                let oldest = windows.iter().min_by_key(|(_, w)| w.started);
                if let Some(oldest) = oldest.map(|(k, _)| k.clone()) {
                    windows.remove(&oldest);
                }
            }
        }
        let window = windows.entry(key).or_insert(Window {
            started: now,
            failures: 0,
        });
        if now.saturating_duration_since(window.started) >= self.window {
            *window = Window {
                started: now,
                failures: 0,
            };
        }
        window.failures += 1;
    }

    pub fn clear(&self, key: &K) {
        self.windows.lock().unwrap().remove(key);
    }
}

/// The key an address is counted under. The addresses in one IPv6 /64
/// usually belong to one network, so they share a count.
pub fn network(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !(u128::MAX >> 64))),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_out_until_the_window_ends() {
        let limiter = Limiter::new(2, Duration::from_secs(60), 10);
        let start = Instant::now();
        limiter.fail("a", start);
        assert_eq!(limiter.retry_after(&"a", start), None);
        limiter.fail("a", start);
        let later = start + Duration::from_secs(20);
        assert_eq!(
            limiter.retry_after(&"a", later),
            Some(Duration::from_secs(40))
        );
        assert_eq!(limiter.retry_after(&"b", later), None);
        assert_eq!(
            limiter.retry_after(&"a", start + Duration::from_secs(60)),
            None
        );
        // A failure after the window starts a new count.
        limiter.fail("a", start + Duration::from_secs(61));
        assert_eq!(
            limiter.retry_after(&"a", start + Duration::from_secs(61)),
            None
        );
        limiter.fail("a", start);
        limiter.clear(&"a");
        assert_eq!(limiter.retry_after(&"a", start), None);
    }

    #[test]
    fn stays_within_capacity() {
        let limiter = Limiter::new(1, Duration::from_secs(60), 3);
        let start = Instant::now();
        for (i, key) in [1, 2, 3, 4].into_iter().enumerate() {
            limiter.fail(key, start + Duration::from_secs(i as u64));
        }
        let now = start + Duration::from_secs(5);
        // The oldest made room for the newest.
        assert_eq!(limiter.retry_after(&1, now), None);
        assert!(limiter.retry_after(&4, now).is_some());
        assert_eq!(limiter.windows.lock().unwrap().len(), 3);
    }

    #[test]
    fn groups_ipv6_by_network() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(network(ip("2001:db8:1:2:aaaa::1")), ip("2001:db8:1:2::"));
        assert_eq!(network(ip("192.0.2.7")), ip("192.0.2.7"));
        assert_eq!(network(ip("::ffff:192.0.2.7")), ip("192.0.2.7"));
    }
}
