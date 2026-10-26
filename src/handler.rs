use std::sync::Arc;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use tracing::{debug, warn};

use crate::blocklist::{Blocklist, Verdict};
use crate::cache::{Cache, CacheKey};
use crate::config::{BlockMode, BlockingConfig};
use crate::upstream::Upstreams;

/// EDNS payload size we advertise, per the DNS Flag Day 2020 recommendation.
const EDNS_PAYLOAD: u16 = 1232;

/// Turns a client query into a response: blocklist, then cache, then upstream.
pub struct Handler {
    blocklist: Arc<Blocklist>,
    block_mode: BlockMode,
    blocked_ttl: u32,
    cache: Cache,
    upstreams: Upstreams,
}

impl Handler {
    pub fn new(
        blocklist: Arc<Blocklist>,
        blocking: &BlockingConfig,
        cache: Cache,
        upstreams: Upstreams,
    ) -> Self {
        Self {
            blocklist,
            block_mode: blocking.mode,
            blocked_ttl: blocking.blocked_ttl,
            cache,
            upstreams,
        }
    }

    /// Handles one wire-format query. Returns `None` when the bytes are too
    /// broken to even answer with FORMERR.
    pub async fn handle_bytes(&self, bytes: &[u8]) -> Option<Message> {
        match Message::from_vec(bytes) {
            Ok(request) => Some(self.handle(&request).await),
            Err(e) => {
                debug!(error = %e, "malformed query");
                let id = u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]);
                Some(Message::error_msg(id, OpCode::Query, ResponseCode::FormErr))
            }
        }
    }

    pub async fn handle(&self, request: &Message) -> Message {
        if request.message_type != MessageType::Query {
            return error_response(request, ResponseCode::FormErr);
        }
        if request.op_code != OpCode::Query {
            return error_response(request, ResponseCode::NotImp);
        }
        let [query] = request.queries.as_slice() else {
            return error_response(request, ResponseCode::FormErr);
        };

        let mut name = query.name().to_lowercase();
        name.set_fqdn(true);
        let ascii = name.to_ascii();
        let lookup = ascii.trim_end_matches('.');

        if self.blocklist.enabled()
            && let Verdict::Blocked(rule) = self.blocklist.rules().check(lookup)
        {
            debug!(name = lookup, rule, "blocked");
            return self.blocked_response(request, query);
        }

        let dnssec_ok = request.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
        let key = CacheKey {
            name,
            query_type: query.query_type(),
            query_class: query.query_class(),
            dnssec_ok,
            checking_disabled: request.checking_disabled,
        };

        if let Some(cached) = self.cache.get(&key).await {
            debug!(name = lookup, qtype = %query.query_type(), "cache hit");
            return finish(request, cached);
        }

        match self
            .upstreams
            .resolve(&upstream_query(request, query, dnssec_ok))
            .await
        {
            Ok(response) => {
                self.cache.insert(key, &response).await;
                finish(request, response)
            }
            Err(e) => {
                warn!(name = lookup, error = %format!("{e:#}"), "all upstreams failed");
                error_response(request, ResponseCode::ServFail)
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
    use crate::config::{CacheConfig, UpstreamConfig};
    use std::str::FromStr;

    use hickory_proto::rr::Name;

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
            Cache::new(CacheConfig::default()),
            upstreams,
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
            .handle(&request("tracker.ads.example.com.", RecordType::A))
            .await;
        assert_eq!(response.id, 4242);
        assert_eq!(response.response_code, ResponseCode::NXDomain);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn blocks_with_null_ip() {
        let h = handler(BlockMode::NullIp);
        let a = h.handle(&request("ads.example.com.", RecordType::A)).await;
        assert_eq!(a.response_code, ResponseCode::NoError);
        assert_eq!(a.answers[0].data, RData::A(A::new(0, 0, 0, 0)));

        let txt = h
            .handle(&request("ads.example.com.", RecordType::TXT))
            .await;
        assert_eq!(txt.response_code, ResponseCode::NoError);
        assert!(txt.answers.is_empty());
    }

    #[tokio::test]
    async fn upstream_failure_is_servfail() {
        let response = handler(BlockMode::Nxdomain)
            .handle(&request("example.org.", RecordType::A))
            .await;
        assert_eq!(response.response_code, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn rejects_non_query_opcodes() {
        let mut req = request("example.org.", RecordType::A);
        req.metadata.op_code = OpCode::Update;
        let response = handler(BlockMode::Nxdomain).handle(&req).await;
        assert_eq!(response.response_code, ResponseCode::NotImp);
    }

    #[tokio::test]
    async fn malformed_bytes_get_formerr() {
        let response = handler(BlockMode::Nxdomain)
            .handle_bytes(&[0x12, 0x34, 0xff])
            .await
            .unwrap();
        assert_eq!(response.id, 0x1234);
        assert_eq!(response.response_code, ResponseCode::FormErr);
    }
}
