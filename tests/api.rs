//! The HTTP API, driven over real HTTP against handler-produced stats.

use std::str::FromStr;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use dns::api::{ApiState, router};
use dns::blocklist::Blocklist;
use dns::cache::Cache;
use dns::config::{BlockingConfig, CacheConfig, StatsConfig, UpstreamConfig};
use dns::handler::Handler;
use dns::stats::Stats;
use dns::upstream::Upstreams;

struct Fixture {
    base: String,
    http: reqwest::Client,
    handler: Handler,
}

async fn start(token: Option<&str>) -> Fixture {
    let blocking = BlockingConfig {
        denylist: vec!["ads.example.com".into()],
        ..BlockingConfig::default()
    };
    let blocklist = Arc::new(Blocklist::new(blocking.clone()).unwrap());
    let cache = Arc::new(Cache::new(CacheConfig::default()));
    let stats = Arc::new(Stats::new(&StatsConfig::default()));
    // Nothing listens on the discard port, so forwarded queries fail fast.
    let upstreams = Upstreams::new(&UpstreamConfig {
        servers: vec!["127.0.0.1:9".parse().unwrap()],
        timeout_ms: 200,
        ..UpstreamConfig::default()
    })
    .unwrap();
    let handler = Handler::new(
        Arc::clone(&blocklist),
        &blocking,
        Arc::clone(&cache),
        upstreams,
        Arc::clone(&stats),
    );

    let state = ApiState {
        blocklist,
        cache,
        stats,
        token: token.map(Arc::from),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(state)).await });

    Fixture {
        base: format!("http://{addr}"),
        http: reqwest::Client::builder().no_proxy().build().unwrap(),
        handler,
    }
}

fn query(name: &str) -> Message {
    let mut msg = Message::new(7, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    msg
}

impl Fixture {
    async fn get(&self, path: &str) -> Value {
        let response = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "GET {path}: {}",
            response.status()
        );
        response.json().await.unwrap()
    }

    async fn put(&self, path: &str, body: Value) -> reqwest::Response {
        self.http
            .put(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn reports_query_stats() {
    let api = start(None).await;
    api.handler.handle(&query("ads.example.com.")).await;
    api.handler.handle(&query("x.ads.example.com.")).await;
    api.handler.handle(&query("example.org.")).await;

    let stats = api.get("/api/stats?top=5").await;
    assert_eq!(stats["queries"]["total"], 3);
    assert_eq!(stats["queries"]["blocked"], 2);
    // The upstream is unreachable, so the forwarded query counts as failed.
    assert_eq!(stats["queries"]["failed"], 1);
    assert_eq!(stats["top_blocked"].as_array().unwrap().len(), 2);

    let response = api
        .http
        .delete(format!("{}/api/stats", api.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    assert_eq!(api.get("/api/stats").await["queries"]["total"], 0);
}

#[tokio::test]
async fn toggles_and_pauses_blocking() {
    let api = start(None).await;
    assert_eq!(api.get("/api/blocking").await["active"], true);

    let off = api.put("/api/blocking", json!({"enabled": false})).await;
    assert_eq!(off.status(), 200);
    assert_eq!(off.json::<Value>().await.unwrap()["active"], false);
    let response = api.handler.handle(&query("ads.example.com.")).await;
    assert_ne!(
        response.response_code,
        hickory_proto::op::ResponseCode::NXDomain
    );

    let paused = api
        .put(
            "/api/blocking",
            json!({"enabled": false, "pause_secs": 300}),
        )
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(paused["active"], false);
    assert!(paused["paused_for_secs"].as_u64().unwrap() > 290);

    let on = api.put("/api/blocking", json!({"enabled": true})).await;
    let on = on.json::<Value>().await.unwrap();
    assert_eq!(on["active"], true);
    assert!(on["paused_for_secs"].is_null());

    let bad = api
        .put("/api/blocking", json!({"enabled": true, "pause_secs": 5}))
        .await;
    assert_eq!(bad.status(), 422);
}

#[tokio::test]
async fn checks_names_and_reports_rules() {
    let api = start(None).await;
    let hit = api.get("/api/check?name=Tracker.Ads.Example.com.").await;
    assert_eq!(hit["name"], "tracker.ads.example.com");
    assert_eq!(hit["blocked"], true);
    assert_eq!(hit["rule"], "ads.example.com");

    let miss = api.get("/api/check?name=example.org").await;
    assert_eq!(miss["blocked"], false);

    let blocking = api.get("/api/blocking").await;
    assert_eq!(blocking["blocked_domains"], 1);

    let reloaded = api
        .http
        .post(format!("{}/api/blocking/reload", api.base))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(reloaded["last_reload"].as_u64().is_some());
}

#[tokio::test]
async fn requires_token_when_configured() {
    let api = start(Some("s3cret")).await;
    let url = format!("{}/api/stats", api.base);

    let none = api.http.get(&url).send().await.unwrap();
    assert_eq!(none.status(), 401);
    let wrong = api.http.get(&url).bearer_auth("nope").send().await.unwrap();
    assert_eq!(wrong.status(), 401);
    let right = api
        .http
        .get(&url)
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(right.status(), 200);

    // Health checks work without a token so container probes stay simple.
    let health = api
        .http
        .get(format!("{}/api/health", api.base))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
}

#[tokio::test]
async fn reports_and_clears_cache() {
    let api = start(None).await;
    assert_eq!(api.get("/api/cache").await["entries"], 0);
    let response = api
        .http
        .delete(format!("{}/api/cache", api.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
}
