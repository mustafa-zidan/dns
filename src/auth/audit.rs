//! A record of sign-ins and of changes made through the API.
//!
//! Each event is logged with the target `hushdns::audit`, and the latest are
//! kept in memory for the dashboard.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::SystemTime;

use serde::Serialize;
use tracing::{info, warn};

/// Events kept in memory. Older ones are only in the logs.
const CAPACITY: usize = 200;

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    /// Unix time, in seconds.
    pub time: u64,
    /// The account or API token, or `anonymous` when the API needs none.
    pub user: String,
    pub action: &'static str,
    pub detail: String,
    /// Where a sign-in came from, as the server saw it.
    pub address: Option<IpAddr>,
}

#[derive(Default)]
pub struct AuditLog {
    events: Mutex<VecDeque<Event>>,
}

impl AuditLog {
    pub fn record(&self, user: &str, action: &'static str, detail: String) {
        self.push(user, action, detail, None, false);
    }

    /// Records a sign-in attempt. Failures are logged as warnings.
    pub fn sign_in(&self, user: &str, action: &'static str, address: Option<IpAddr>, ok: bool) {
        self.push(user, action, String::new(), address, !ok);
    }

    fn push(
        &self,
        user: &str,
        action: &'static str,
        detail: String,
        address: Option<IpAddr>,
        failure: bool,
    ) {
        let shown = address.map(tracing::field::display);
        let details = (!detail.is_empty()).then_some(detail.as_str());
        if failure {
            warn!(target: "hushdns::audit", user, address = shown, detail = details, "{action}");
        } else {
            info!(target: "hushdns::audit", user, address = shown, detail = details, "{action}");
        }
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut events = self.events.lock().unwrap();
        if events.len() == CAPACITY {
            events.pop_front();
        }
        events.push_back(Event {
            time,
            user: user.to_owned(),
            action,
            detail,
            address,
        });
    }

    /// The latest events, newest first.
    pub fn recent(&self) -> Vec<Event> {
        self.events.lock().unwrap().iter().rev().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_latest_events() {
        let log = AuditLog::default();
        for i in 0..CAPACITY + 5 {
            log.record("admin", "cache cleared", i.to_string());
        }
        let recent = log.recent();
        assert_eq!(recent.len(), CAPACITY);
        assert_eq!(recent[0].detail, (CAPACITY + 4).to_string());
        assert_eq!(recent[CAPACITY - 1].detail, "5");
    }
}
