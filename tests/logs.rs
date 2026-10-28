//! The per-query log, as JSON. Its own test binary, because tracing caches
//! whether a callsite is enabled across threads, and tests running in
//! parallel without a subscriber would race with this one.

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};

use hushdns::blocklist::Blocklist;
use hushdns::cache::Cache;
use hushdns::config::{BlockingConfig, CacheConfig, StatsConfig, UpstreamConfig};
use hushdns::handler::{Handler, Peer, Transport};
use hushdns::stats::Stats;
use hushdns::upstream::Upstreams;

/// Collects what a subscriber writes.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn logs_each_query_with_searchable_fields() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_env_filter("hushdns::query=debug")
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let blocking = BlockingConfig {
        denylist: vec!["ads.example.com".into()],
        ..BlockingConfig::default()
    };
    let handler = Handler::new(
        Arc::new(Blocklist::new(blocking.clone()).unwrap()),
        &blocking,
        Arc::new(Cache::new(CacheConfig::default())),
        Upstreams::new(&UpstreamConfig {
            servers: vec!["127.0.0.1:9".parse().unwrap()],
            timeout_ms: 200,
            ..UpstreamConfig::default()
        })
        .unwrap(),
        Arc::new(Stats::new(&StatsConfig::default())),
    );
    let mut request = Message::new(1, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_str("Tracker.Ads.Example.com.").unwrap(),
        RecordType::AAAA,
    ));
    let doh = Peer::new("192.168.1.20".parse().unwrap(), Transport::Doh);
    handler.handle(&request, doh).await;
    let udp = Peer::new("127.0.0.1".parse().unwrap(), Transport::Udp);
    handler.handle_bytes(&[0x12, 0x34, 0xff], udp).await;

    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{text}");
    let blocked = &lines[0];
    assert_eq!(blocked["target"], "hushdns::query");
    assert_eq!(blocked["message"], "query");
    assert_eq!(blocked["name"], "tracker.ads.example.com");
    assert_eq!(blocked["qtype"], "AAAA");
    assert_eq!(blocked["outcome"], "blocked");
    assert_eq!(blocked["rcode"], "NXDomain");
    assert_eq!(blocked["rule"], "ads.example.com");
    assert_eq!(blocked["client_ip"], "192.168.1.20");
    assert_eq!(blocked["transport"], "doh");
    assert!(blocked["duration_ms"].as_f64().is_some());
    assert_eq!(lines[1]["outcome"], "invalid");
    assert_eq!(lines[1]["client_ip"], "127.0.0.1");
}
