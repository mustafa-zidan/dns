use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use tracing::{debug, warn};

use crate::blocklist::Blocklist;
use crate::cache::{Cache, CacheKey};
use crate::config::{BlockMode, BlockingConfig};
use crate::stats::{Outcome, Stats};
use crate::upstream::Upstreams;

/// EDNS payload size we advertise, per the DNS Flag Day 2020 recommendation.
const EDNS_PAYLOAD: u16 = 1232;

/// How a query reached the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    /// DNS-over-TLS.
    Dot,
    /// DNS-over-HTTPS.
    Doh,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
            Transport::Dot => "dot",
            Transport::Doh => "doh",
        }
    }
}

/// Who sent a query, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub ip: IpAddr,
    pub transport: Transport,
}

impl Peer {
    pub fn new(ip: IpAddr, transport: Transport) -> Self {
        Self { ip, transport }
    }
}

/// What [`Handler::answer`] decided, for stats and the query log.
struct Answered {
    response: Message,
    outcome: Outcome,
    /// The rule that blocked the query.
    rule: Option<String>,
    /// The client group whose rules blocked it.
    group: Option<String>,
}

/// Turns a client query into a response: blocklist, then cache, then upstream.
pub struct Handler {
    blocklist: Arc<Blocklist>,
    block_mode: BlockMode,
    blocked_ttl: u32,
    cache: Arc<Cache>,
    upstreams: Upstreams,
    stats: Arc<Stats>,
}

impl Handler {
    pub fn new(
        blocklist: Arc<Blocklist>,
        blocking: &BlockingConfig,
        cache: Arc<Cache>,
        upstreams: Upstreams,
        stats: Arc<Stats>,
    ) -> Self {
        Self {
            blocklist,
            block_mode: blocking.mode,
            blocked_ttl: blocking.blocked_ttl,
            cache,
            upstreams,
            stats,
        }
    }

    /// Handles one wire-format query from `peer`. Returns `None` when the
    /// bytes are too broken to even answer with FORMERR.
    pub async fn handle_bytes(&self, bytes: &[u8], peer: Peer) -> Option<Message> {
        match Message::from_vec(bytes) {
            Ok(request) => Some(self.handle(&request, peer).await),
            Err(e) => {
                debug!(
                    target: "dns::query",
                    client_ip = %peer.ip,
                    transport = peer.transport.as_str(),
                    outcome = Outcome::Invalid.as_str(),
                    error = %e,
                    "malformed query"
                );
                self.stats.record(None, Outcome::Invalid);
                let id = u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]);
                Some(Message::error_msg(id, OpCode::Query, ResponseCode::FormErr))
            }
        }
    }

    /// Answers one query, counts it, and logs it on the `dns::query` target
    /// at debug level, with the same field names every time so the log can
    /// be searched.
    pub async fn handle(&self, request: &Message, peer: Peer) -> Message {
        let started = Instant::now();
        let name = request.queries.first().map(|q| {
            let ascii = q.name().to_lowercase().to_ascii();
            ascii.trim_end_matches('.').to_string()
        });
        let answered = self.answer(request, peer, name.as_deref()).await;
        let counted = (answered.outcome != Outcome::Invalid)
            .then_some(name.as_deref())
            .flatten();
        self.stats.record(counted, answered.outcome);
        debug!(
            target: "dns::query",
            name = name.as_deref(),
            qtype = request.queries.first().map(|q| q.query_type().to_string()),
            outcome = answered.outcome.as_str(),
            rcode = ?answered.response.response_code,
            rule = answered.rule.as_deref(),
            client_ip = %peer.ip,
            client_group = answered.group.as_deref(),
            transport = peer.transport.as_str(),
            duration_ms = started.elapsed().as_secs_f64() * 1000.0,
            "query"
        );
        answered.response
    }

    async fn answer(&self, request: &Message, peer: Peer, lookup: Option<&str>) -> Answered {
        let done = |response, outcome| Answered {
            response,
            outcome,
            rule: None,
            group: None,
        };
        let invalid = |code| done(error_response(request, code), Outcome::Invalid);
        if request.message_type != MessageType::Query {
            return invalid(ResponseCode::FormErr);
        }
        if request.op_code != OpCode::Query {
            return invalid(ResponseCode::NotImp);
        }
        let ([query], Some(lookup)) = (request.queries.as_slice(), lookup) else {
            return invalid(ResponseCode::FormErr);
        };

        if self.blocklist.enabled()
            && let Some((rule, group)) = self.blocklist.blocked_by(lookup, Some(peer.ip))
        {
            return Answered {
                response: self.blocked_response(request, query),
                outcome: Outcome::Blocked,
                rule: Some(rule),
                group: group.map(str::to_string),
            };
        }

        let mut name = query.name().to_lowercase();
        name.set_fqdn(true);
        let dnssec_ok = request.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
        let key = CacheKey {
            name,
            query_type: query.query_type(),
            query_class: query.query_class(),
            dnssec_ok,
            checking_disabled: request.checking_disabled,
        };

        if let Some(cached) = self.cache.get(&key).await {
            return done(finish(request, cached), Outcome::Cached);
        }

        match self
            .upstreams
            .resolve(&upstream_query(request, query, dnssec_ok))
            .await
        {
            Ok(response) => {
                self.cache.insert(key, &response).await;
                done(finish(request, response), Outcome::Forwarded)
            }
            Err(e) => {
                warn!(name = lookup, error = %format!("{e:#}"), "all upstreams failed");
                done(
                    error_response(request, ResponseCode::ServFail),
                    Outcome::Failed,
                )
            }
        }
    }

    fn blocked_response(&self, request: &Message, query: &Query) -> Message {
        let code = match self.block_mode {
            BlockMode::Nxdomain => ResponseCode::NXDomain,
            BlockMode::Refused => ResponseCode::Refused,
            BlockMode::NullIp => ResponseCode::NoError,
        };
        let mut response = error_response(request, code);
        if self.block_mode == BlockMode::NullIp {
            let rdata = match query.query_type() {
                RecordType::A => Some(RData::A(A::new(0, 0, 0, 0))),
                RecordType::AAAA => Some(RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 0))),
                _ => None,
            };
            if let Some(rdata) = rdata {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    self.blocked_ttl,
                    rdata,
                ));
            }
        }
        response
    }
}

/// Builds the query sent upstream. It gets a fresh random ID and carries none
/// of the client's EDNS options, so things like EDNS Client Subnet never leak.
fn upstream_query(request: &Message, query: &Query, dnssec_ok: bool) -> Message {
    let mut upstream = Message::query();
    upstream.metadata.recursion_desired = true;
    upstream.metadata.checking_disabled = request.checking_disabled;
    upstream.add_query(query.clone());
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    edns.set_dnssec_ok(dnssec_ok);
    upstream.set_edns(edns);
    upstream
}

/// Rewrites an upstream or cached answer so it replies to `request`.
fn finish(request: &Message, mut response: Message) -> Message {
    response.metadata.id = request.id;
    response.metadata.recursion_desired = request.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries = request.queries.clone();
    response.edns = request
        .edns
        .as_ref()
        .map(|e| response_edns(e.flags().dnssec_ok));
    response
}

fn error_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(request.id, request.op_code);
    response.metadata.recursion_desired = request.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.checking_disabled = request.checking_disabled;
    response.metadata.response_code = code;
    response.queries = request.queries.clone();
    if let Some(edns) = &request.edns {
        response.set_edns(response_edns(edns.flags().dnssec_ok));
    }
    response
}

fn response_edns(dnssec_ok: bool) -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    edns.set_dnssec_ok(dnssec_ok);
    edns
}

/// Largest UDP response the client said it accepts.
pub fn client_max_payload(request_bytes: &[u8]) -> usize {
    Message::from_vec(request_bytes)
        .ok()
        .and_then(|m| m.edns.map(|e| e.max_payload()))
        .map_or(512, |p| usize::from(p.clamp(512, EDNS_PAYLOAD)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CacheConfig, StatsConfig, UpstreamConfig};
    use std::str::FromStr;

    use hickory_proto::rr::Name;

    const LOCAL: Peer = Peer {
        ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        transport: Transport::Udp,
    };

    fn handler(mode: BlockMode) -> Handler {
        let blocking = BlockingConfig {
            mode,
            denylist: vec!["ads.example.com".into()],
            ..BlockingConfig::default()
        };
        // Port 9 (discard) on loopback: nothing answers, so upstream queries fail fast.
        let upstreams = Upstreams::new(&UpstreamConfig {
            servers: vec!["127.0.0.1:9".parse().unwrap()],
            timeout_ms: 200,
            ..UpstreamConfig::default()
        })
        .unwrap();
        Handler::new(
            Arc::new(Blocklist::new(blocking.clone()).unwrap()),
            &blocking,
            Arc::new(Cache::new(CacheConfig::default())),
            upstreams,
            Arc::new(Stats::new(&StatsConfig::default())),
        )
    }

    fn request(name: &str, qtype: RecordType) -> Message {
        let mut msg = Message::new(4242, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
        msg
    }

    #[tokio::test]
    async fn blocks_with_nxdomain() {
        let response = handler(BlockMode::Nxdomain)
            .handle(&request("tracker.ads.example.com.", RecordType::A), LOCAL)
            .await;
        assert_eq!(response.id, 4242);
        assert_eq!(response.response_code, ResponseCode::NXDomain);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn blocks_with_null_ip() {
        let h = handler(BlockMode::NullIp);
        let a = h
            .handle(&request("ads.example.com.", RecordType::A), LOCAL)
            .await;
        assert_eq!(a.response_code, ResponseCode::NoError);
        assert_eq!(a.answers[0].data, RData::A(A::new(0, 0, 0, 0)));

        let txt = h
            .handle(&request("ads.example.com.", RecordType::TXT), LOCAL)
            .await;
        assert_eq!(txt.response_code, ResponseCode::NoError);
        assert!(txt.answers.is_empty());
    }

    #[tokio::test]
    async fn upstream_failure_is_servfail() {
        let response = handler(BlockMode::Nxdomain)
            .handle(&request("example.org.", RecordType::A), LOCAL)
            .await;
        assert_eq!(response.response_code, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn rejects_non_query_opcodes() {
        let mut req = request("example.org.", RecordType::A);
        req.metadata.op_code = OpCode::Update;
        let response = handler(BlockMode::Nxdomain).handle(&req, LOCAL).await;
        assert_eq!(response.response_code, ResponseCode::NotImp);
    }

    #[tokio::test]
    async fn malformed_bytes_get_formerr() {
        let response = handler(BlockMode::Nxdomain)
            .handle_bytes(&[0x12, 0x34, 0xff], LOCAL)
            .await
            .unwrap();
        assert_eq!(response.id, 0x1234);
        assert_eq!(response.response_code, ResponseCode::FormErr);
    }
}
