use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use moka::Expiry;
use moka::future::Cache as MokaCache;

use crate::config::CacheConfig;

/// Identifies a cached answer. DO and CD change what upstreams return, so
/// they are part of the key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: Name,
    pub query_type: RecordType,
    pub query_class: DNSClass,
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
}

#[derive(Debug, Clone)]
struct Entry {
    message: Arc<Message>,
    inserted: Instant,
    ttl: u32,
}

struct EntryExpiry;

impl Expiry<CacheKey, Entry> for EntryExpiry {
    fn expire_after_create(&self, _: &CacheKey, entry: &Entry, _: Instant) -> Option<Duration> {
        Some(Duration::from_secs(entry.ttl.into()))
    }
}

/// A TTL-aware response cache.
pub struct Cache {
    inner: Option<MokaCache<CacheKey, Entry>>,
    config: CacheConfig,
}

impl Cache {
    pub fn new(config: CacheConfig) -> Self {
        let inner = config.enabled.then(|| {
            MokaCache::builder()
                .max_capacity(config.max_entries)
                .expire_after(EntryExpiry)
                .build()
        });
        Self { inner, config }
    }

    /// Returns a cached response with TTLs reduced by the time it spent in the cache.
    pub async fn get(&self, key: &CacheKey) -> Option<Message> {
        let entry = self.inner.as_ref()?.get(key).await?;
        let elapsed = u32::try_from(entry.inserted.elapsed().as_secs()).unwrap_or(u32::MAX);
        if elapsed >= entry.ttl {
            return None;
        }
        let mut message = (*entry.message).clone();
        for record in message
            .answers
            .iter_mut()
            .chain(message.authorities.iter_mut())
            .chain(message.additionals.iter_mut())
        {
            record.ttl = record.ttl.saturating_sub(elapsed);
        }
        Some(message)
    }

    /// Stores `response` if it is cacheable.
    pub async fn insert(&self, key: CacheKey, response: &Message) {
        let Some(inner) = &self.inner else { return };
        let Some(ttl) = self.ttl_for(response) else {
            return;
        };
        if ttl == 0 {
            return;
        }
        let entry = Entry {
            message: Arc::new(response.clone()),
            inserted: Instant::now(),
            ttl,
        };
        inner.insert(key, entry).await;
    }

    /// Picks the TTL to cache `response` for, or `None` if it should not be cached.
    fn ttl_for(&self, response: &Message) -> Option<u32> {
        if response.truncation {
            return None;
        }
        let ttl = match response.response_code {
            ResponseCode::NoError if !response.answers.is_empty() => response
                .answers
                .iter()
                .chain(response.authorities.iter())
                .map(|r| r.ttl)
                .min()?,
            // NODATA and NXDOMAIN: RFC 2308 says to use the SOA's minimum field.
            ResponseCode::NoError | ResponseCode::NXDomain => response
                .authorities
                .iter()
                .find_map(|r| match &r.data {
                    RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
                    _ => None,
                })
                .unwrap_or(self.config.negative_ttl),
            _ => return None,
        };
        Some(ttl.clamp(
            self.config.min_ttl,
            self.config.max_ttl.max(self.config.min_ttl),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::A;
    use std::str::FromStr;

    fn key(name: &str) -> CacheKey {
        CacheKey {
            name: Name::from_str(name).unwrap(),
            query_type: RecordType::A,
            query_class: DNSClass::IN,
            dnssec_ok: false,
            checking_disabled: false,
        }
    }

    fn answer(name: &str, ttl: u32) -> Message {
        let name = Name::from_str(name).unwrap();
        let mut msg = Message::new(1, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            name,
            ttl,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        msg
    }

    #[tokio::test]
    async fn caches_and_returns_answers() {
        let cache = Cache::new(CacheConfig::default());
        cache
            .insert(key("example.com."), &answer("example.com.", 300))
            .await;
        let hit = cache.get(&key("example.com.")).await.unwrap();
        assert_eq!(hit.answers.len(), 1);
        assert!(hit.answers[0].ttl <= 300);
        assert!(cache.get(&key("other.com.")).await.is_none());
    }

    #[tokio::test]
    async fn skips_zero_ttl_and_servfail() {
        let cache = Cache::new(CacheConfig::default());
        cache
            .insert(key("zero.com."), &answer("zero.com.", 0))
            .await;
        assert!(cache.get(&key("zero.com.")).await.is_none());

        let mut fail = answer("fail.com.", 300);
        fail.metadata.response_code = ResponseCode::ServFail;
        cache.insert(key("fail.com."), &fail).await;
        assert!(cache.get(&key("fail.com.")).await.is_none());
    }

    #[tokio::test]
    async fn clamps_ttl() {
        let cache = Cache::new(CacheConfig {
            max_ttl: 60,
            ..CacheConfig::default()
        });
        assert_eq!(cache.ttl_for(&answer("a.com.", 3600)), Some(60));
    }

    #[tokio::test]
    async fn negative_answers_use_negative_ttl() {
        let cache = Cache::new(CacheConfig::default());
        let mut nx = Message::new(1, MessageType::Response, OpCode::Query);
        nx.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(cache.ttl_for(&nx), Some(300));
    }

    #[tokio::test]
    async fn disabled_cache_stores_nothing() {
        let cache = Cache::new(CacheConfig {
            enabled: false,
            ..CacheConfig::default()
        });
        cache
            .insert(key("example.com."), &answer("example.com.", 300))
            .await;
        assert!(cache.get(&key("example.com.")).await.is_none());
    }
}
