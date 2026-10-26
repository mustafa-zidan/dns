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
    start_with(token, true).await
}

async fn start_with(token: Option<&str>, dashboard: bool) -> Fixture {
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
        dashboard,
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

#[tokio::test]
async fn serves_dashboard_with_strict_headers() {
    let api = start(None).await;
    let page = api.http.get(&api.base).send().await.unwrap();
    assert_eq!(page.status(), 200);
    let csp = page.headers()["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'self'"));
    assert_eq!(page.headers()["x-frame-options"], "DENY");
    assert!(page.text().await.unwrap().contains("app.js"));

    for (path, kind) in [("/app.js", "text/javascript"), ("/app.css", "text/css")] {
        let asset = api
            .http
            .get(format!("{}{path}", api.base))
            .send()
            .await
            .unwrap();
        assert_eq!(asset.status(), 200, "{path}");
        assert!(
            asset.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with(kind)
        );
    }

    let off = start_with(None, false).await;
    let page = off.http.get(&off.base).send().await.unwrap();
    assert_eq!(page.status(), 404);
}

#[tokio::test]
async fn rejects_rebound_hosts_and_cross_site_requests() {
    let api = start(None).await;
    let url = format!("{}/api/stats", api.base);

    // A hostile page re-pointed at 127.0.0.1 still sends its own host name.
    let rebound = api
        .http
        .get(&url)
        .header("host", "evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(rebound.status(), 403);

    let cross_site = api
        .http
        .post(format!("{}/api/blocking/reload", api.base))
        .header("origin", "http://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(cross_site.status(), 403);

    let host = api.base.trim_start_matches("http://");
    let same_site = api
        .http
        .get(&url)
        .header("origin", format!("http://{host}"))
        .send()
        .await
        .unwrap();
    assert_eq!(same_site.status(), 200);

    // With a token, a hostname is fine: the attacker's origin has no token.
    let named = start(Some("s3cret")).await;
    let response = named
        .http
        .get(format!("{}/api/stats", named.base))
        .header("host", "dns.lan")
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}
