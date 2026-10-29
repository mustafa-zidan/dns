//! The HTTP API, driven over real HTTP against handler-produced stats.

use std::str::FromStr;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use hushdns::api::{ApiState, router};
use hushdns::auth::{self, Auth, Role};
use hushdns::blocklist::Blocklist;
use hushdns::cache::Cache;
use hushdns::clients::Clients;
use hushdns::config::{
    ApiConfig, BlockingConfig, CacheConfig, Config, StatsConfig, TokenConfig, UpstreamConfig,
    UserConfig,
};
use hushdns::handler::{Handler, Peer, Transport};
use hushdns::stats::Stats;
use hushdns::upstream::Upstreams;

struct Fixture {
    base: String,
    http: reqwest::Client,
    handler: Handler,
}

async fn start(token: Option<&str>) -> Fixture {
    start_with(token, &[]).await
}

async fn start_with(token: Option<&str>, cors_origins: &[&str]) -> Fixture {
    start_api(ApiConfig {
        token: token.map(String::from),
        cors_origins: cors_origins.iter().map(|o| o.to_string()).collect(),
        ..ApiConfig::default()
    })
    .await
}

async fn start_api(api: ApiConfig) -> Fixture {
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
        auth: Arc::new(Auth::new(&api).unwrap()),
        cors_origins: api.cors_origins.into(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await });

    Fixture {
        base: format!("http://{addr}"),
        http: reqwest::Client::builder().no_proxy().build().unwrap(),
        handler,
    }
}

const LOCAL: Peer = Peer {
    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    transport: Transport::Udp,
};

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

const ADMIN_TOKEN: &str = "hdt_admin-test-token";
const VIEWER_TOKEN: &str = "hdt_viewer-test-token";

/// An API with an admin and a viewer account, and a token for each role.
async fn start_accounts() -> Fixture {
    let hash = auth::hash_password("correct horse").unwrap();
    let user = |name: &str, role| UserConfig {
        name: name.into(),
        password_hash: hash.clone(),
        role,
    };
    let token = |name: &str, secret: &str, role| TokenConfig {
        name: name.into(),
        hash: sha256_hex(secret),
        role,
    };
    start_api(ApiConfig {
        users: vec![user("ana", Role::Admin), user("bo", Role::Viewer)],
        tokens: vec![
            token("deploy", ADMIN_TOKEN, Role::Admin),
            token("grafana", VIEWER_TOKEN, Role::Viewer),
        ],
        ..ApiConfig::default()
    })
    .await
}

fn sha256_hex(secret: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(secret.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Fixture {
    async fn login(&self, name: &str, password: &str) -> reqwest::Response {
        self.http
            .post(format!("{}/api/login", self.base))
            .json(&json!({"name": name, "password": password}))
            .send()
            .await
            .unwrap()
    }

    async fn session(&self, name: &str) -> String {
        let response = self.login(name, "correct horse").await;
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        body["token"].as_str().unwrap().to_owned()
    }

    async fn send(&self, method: reqwest::Method, path: &str, bearer: &str) -> reqwest::Response {
        let mut request = self
            .http
            .request(method.clone(), format!("{}{path}", self.base))
            .bearer_auth(bearer);
        if method == reqwest::Method::PUT {
            request = request.json(&json!({"enabled": true}));
        }
        request.send().await.unwrap()
    }
}

#[tokio::test]
async fn signs_in_with_an_account() {
    let api = start_accounts().await;

    let wrong = api.login("ana", "wrong").await;
    assert_eq!(wrong.status(), 401);
    let unknown = api.login("nobody", "correct horse").await;
    assert_eq!(unknown.status(), 401);

    let response = api.login("ana", "correct horse").await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body["user"],
        json!({"name": "ana", "role": "admin", "via": "session"})
    );
    assert_eq!(body["expires_in_secs"], 7 * 86_400);
    let token = body["token"].as_str().unwrap();

    let me = api.send(reqwest::Method::GET, "/api/me", token).await;
    assert_eq!(me.json::<Value>().await.unwrap()["name"], "ana");
    let stats = api.send(reqwest::Method::GET, "/api/stats", token).await;
    assert_eq!(stats.status(), 200);

    let logout = api.send(reqwest::Method::POST, "/api/logout", token).await;
    assert_eq!(logout.status(), 204);
    let after = api.send(reqwest::Method::GET, "/api/stats", token).await;
    assert_eq!(after.status(), 401);

    let audit = api
        .send(reqwest::Method::GET, "/api/audit", ADMIN_TOKEN)
        .await;
    let audit: Value = audit.json().await.unwrap();
    let actions: Vec<_> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        [
            "signed out",
            "signed in",
            "sign-in failed",
            "sign-in failed"
        ]
    );
    assert_eq!(audit[1]["address"], "127.0.0.1");
}

#[tokio::test]
async fn viewers_read_and_admins_change() {
    use reqwest::Method;
    let api = start_accounts().await;
    let ana = api.session("ana").await;
    let bo = api.session("bo").await;

    let reads = [
        "/api/stats",
        "/api/blocking",
        "/api/check?name=example.org",
        "/api/clients",
        "/api/cache",
        "/api/me",
    ];
    let changes = [
        (Method::DELETE, "/api/stats"),
        (Method::PUT, "/api/blocking"),
        (Method::POST, "/api/blocking/reload"),
        (Method::DELETE, "/api/cache"),
    ];
    for viewer in [bo.as_str(), VIEWER_TOKEN] {
        for path in reads {
            let response = api.send(Method::GET, path, viewer).await;
            assert_eq!(response.status(), 200, "viewer GET {path}");
        }
        for (method, path) in &changes {
            let response = api.send(method.clone(), path, viewer).await;
            assert_eq!(response.status(), 403, "viewer {method} {path}");
        }
        let audit = api.send(Method::GET, "/api/audit", viewer).await;
        assert_eq!(audit.status(), 403, "viewer audit");
    }
    for admin in [ana.as_str(), ADMIN_TOKEN] {
        for (method, path) in &changes {
            let response = api.send(method.clone(), path, admin).await;
            assert!(response.status().is_success(), "admin {method} {path}");
        }
        let audit = api.send(Method::GET, "/api/audit", admin).await;
        assert_eq!(audit.status(), 200);
    }

    let audit: Value = api
        .send(Method::GET, "/api/audit", ADMIN_TOKEN)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(audit[0]["user"], "deploy");
    assert_eq!(audit[0]["action"], "cache cleared");
    let by_ana = audit
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "blocking changed" && e["user"] == "ana");
    assert_eq!(by_ana.unwrap()["detail"], "on");

    let me: Value = api
        .send(Method::GET, "/api/me", VIEWER_TOKEN)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        me,
        json!({"name": "grafana", "role": "viewer", "via": "token"})
    );
}

#[tokio::test]
async fn limits_failed_sign_ins() {
    let api = start_accounts().await;
    let mut last = None;
    for _ in 0..12 {
        last = Some(api.login("ana", "guess").await);
    }
    let last = last.unwrap();
    assert_eq!(last.status(), 429);
    let retry: u64 = last.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry > 0 && retry <= 15 * 60 + 1, "{retry}");
    // The other account is not locked out.
    assert_eq!(api.login("bo", "correct horse").await.status(), 200);
}

#[tokio::test]
async fn explains_when_there_are_no_accounts() {
    let api = start(Some("s3cret")).await;
    assert_eq!(api.login("ana", "x").await.status(), 404);
    let open = start(None).await;
    let me = open.get("/api/me").await;
    assert_eq!(
        me,
        json!({"name": "anonymous", "role": "admin", "via": "open"})
    );
}
