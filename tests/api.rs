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
use dns::clients::Clients;
use dns::config::{BlockingConfig, CacheConfig, Config, StatsConfig, UpstreamConfig};
use dns::handler::Handler;
use dns::stats::Stats;
use dns::upstream::Upstreams;

struct Fixture {
    base: String,
    http: reqwest::Client,
    handler: Handler,
}

async fn start(token: Option<&str>) -> Fixture {
    start_with(token, &[]).await
}

async fn start_with(token: Option<&str>, cors_origins: &[&str]) -> Fixture {
    let blocking = BlockingConfig {
        denylist: vec!["ads.example.com".into()],
        ..BlockingConfig::default()
    };
    let clients = Config::parse(
        "[[clients]]\nname = \"kids\"\naddresses = [\"192.168.1.0/24\"]\ndenylist = [\"video.example\"]",
    )
    .unwrap()
    .clients;
    let clients = Arc::new(Clients::new(&clients, None).unwrap());
    let blocklist = Arc::new(
        Blocklist::new(blocking.clone())
            .unwrap()
            .with_clients(clients),
    );
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
        cors_origins: cors_origins.iter().map(|o| o.to_string()).collect(),
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

const LOCAL: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

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
    api.handler.handle(&query("ads.example.com."), LOCAL).await;
    api.handler
        .handle(&query("x.ads.example.com."), LOCAL)
        .await;
    api.handler.handle(&query("example.org."), LOCAL).await;

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
    let response = api.handler.handle(&query("ads.example.com."), LOCAL).await;
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
    assert_eq!(miss["client"], Value::Null);

    let shared = api.get("/api/check?name=video.example").await;
    assert_eq!(shared["blocked"], false);
    let kids = api
        .get("/api/check?name=video.example&client=192.168.1.20")
        .await;
    assert_eq!(kids["blocked"], true);
    assert_eq!(kids["rule"], "video.example");
    assert_eq!(kids["client"], "kids");

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
async fn allows_configured_dashboard_origins() {
    const DASHBOARD: &str = "http://localhost:8080";
    let api = start_with(Some("s3cret"), &[DASHBOARD]).await;
    let url = format!("{}/api/blocking", api.base);

    // The browser's preflight carries no token and must still succeed.
    let preflight = api
        .http
        .request(reqwest::Method::OPTIONS, &url)
        .header("origin", DASHBOARD)
        .header("access-control-request-method", "PUT")
        .header(
            "access-control-request-headers",
            "authorization,content-type",
        )
        .send()
        .await
        .unwrap();
    assert!(preflight.status().is_success(), "{}", preflight.status());
    assert_eq!(
        preflight.headers()["access-control-allow-origin"],
        DASHBOARD
    );
    let allowed = preflight.headers()["access-control-allow-methods"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(allowed.contains("PUT"), "{allowed}");

    let response = api
        .http
        .get(&url)
        .header("origin", DASHBOARD)
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["access-control-allow-origin"], DASHBOARD);
    assert_eq!(
        response.headers()["content-security-policy"],
        "default-src 'none'; frame-ancestors 'none'"
    );

    let other = api
        .http
        .get(&url)
        .header("origin", "http://localhost:9999")
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(other.status(), 403);
    assert!(other.headers().get("access-control-allow-origin").is_none());
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

#[tokio::test]
async fn lists_and_pauses_client_groups() {
    let api = start(None).await;
    let clients = api.get("/api/clients").await;
    let kids = &clients["groups"][0];
    assert_eq!(kids["name"], "kids");
    assert_eq!(kids["addresses"], json!(["192.168.1.0/24"]));
    assert_eq!(kids["denylist"], 1);
    assert_eq!(kids["paused_for_secs"], Value::Null);
    assert_eq!(clients["now"].as_str().unwrap().len(), 16);

    let check = "/api/check?name=video.example&client=192.168.1.20";
    let paused = api
        .put("/api/clients/kids", json!({"pause_secs": 60}))
        .await;
    assert_eq!(paused.status(), 200);
    let paused: Value = paused.json().await.unwrap();
    assert!(paused["paused_for_secs"].as_u64().unwrap() > 50);
    assert_eq!(api.get(check).await["blocked"], false);

    let resumed = api.put("/api/clients/kids", json!({"pause_secs": 0})).await;
    assert_eq!(resumed.status(), 200);
    assert_eq!(api.get(check).await["blocked"], true);

    let missing = api
        .put("/api/clients/nobody", json!({"pause_secs": 0}))
        .await;
    assert_eq!(missing.status(), 404);
}
