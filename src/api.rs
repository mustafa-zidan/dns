//! HTTP API for stats and runtime control.
//!
//! | Method | Path                    | What it does                          | Role   |
//! |--------|-------------------------|---------------------------------------|--------|
//! | GET    | `/api/health`           | Liveness check                        | none   |
//! | POST   | `/api/login`            | `{"name", "password"}` starts a session | none |
//! | POST   | `/api/logout`           | Ends the session                      | any    |
//! | GET    | `/api/me`               | Who the credentials belong to         | any    |
//! | GET    | `/api/stats?top=N`      | Query counters and top domains        | viewer |
//! | DELETE | `/api/stats`            | Reset the counters                    | admin  |
//! | GET    | `/api/blocking`         | Blocking state, rule counts, lists    | viewer |
//! | PUT    | `/api/blocking`         | `{"enabled": bool, "pause_secs": n}`  | admin  |
//! | POST   | `/api/blocking/reload`  | Re-download the blocklists now        | admin  |
//! | GET    | `/api/check?name=x`     | Whether a name is blocked, and by     | viewer |
//! |        | `&client=192.168.1.20`  | which rule, optionally for a client   |        |
//! | GET    | `/api/clients`          | Client groups, lists and schedules    | viewer |
//! | PUT    | `/api/clients/{name}`   | `{"pause_secs": n}`; 0 resumes        | admin  |
//! | GET    | `/api/cache`            | Number of cached answers              | viewer |
//! | DELETE | `/api/cache`            | Empty the cache                       | admin  |
//! | GET    | `/api/audit`            | Recent sign-ins and changes           | admin  |
//!
//! Reading needs the viewer role and every other method needs admin; see
//! [`crate::auth`] for the credentials.
//!
//! The web dashboard is a separate app (see `web/`) that calls this API from
//! the origins listed in `api.cors_origins`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use crate::auth::{Auth, Event, LoginError, Principal, Role, Via};
use crate::blocklist::{Blocklist, SourceStatus};
use crate::cache::Cache;
use crate::clients::ClientStatus;
use crate::stats::{Snapshot, Stats};

const DEFAULT_TOP: usize = 10;
const MAX_TOP: usize = 100;

#[derive(Clone)]
pub struct ApiState {
    pub blocklist: Arc<Blocklist>,
    pub cache: Arc<Cache>,
    pub stats: Arc<Stats>,
    pub auth: Arc<Auth>,
    /// Normalized origins (`scheme://host[:port]`) allowed to call the API
    /// from a browser.
    pub cors_origins: Arc<[String]>,
}

/// Binds the API and serves it until the listener fails.
pub async fn serve(listen: SocketAddr, state: ApiState) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding API on {listen}"))?;
    if !state.auth.required() && !listen.ip().is_loopback() {
        warn!(%listen, "the API is reachable from the network without sign-in; set api.users or api.tokens");
    }
    info!(%listen, "API listening");
    // Client addresses are for limiting failed sign-ins.
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn router(state: ApiState) -> Router {
    // Reading needs a viewer, anything else an admin.
    let control = Router::new()
        .route("/stats", get(get_stats).delete(reset_stats))
        .route("/blocking", get(get_blocking).put(set_blocking))
        .route("/blocking/reload", post(reload_blocking))
        .route("/check", get(check))
        .route("/clients", get(get_clients))
        .route("/clients/{name}", put(set_client))
        .route("/cache", get(get_cache).delete(clear_cache))
        .route_layer(middleware::from_fn(authorize_by_method));
    let admin = Router::new()
        .route("/audit", get(get_audit))
        .route_layer(middleware::from_fn(authorize_admin));
    let signed_in = Router::new()
        .route("/me", get(me))
        .route("/logout", post(logout))
        .merge(control)
        .merge(admin)
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
    let public = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/login", post(login));
    let router = Router::new()
        .nest("/api", signed_in.merge(public))
        .layer(middleware::from_fn_with_state(state.clone(), guard_browser))
        .layer(middleware::from_fn(security_headers));
    // Outermost, so preflight requests are answered before the credentials
    // check.
    let router = match cors(&state.cors_origins) {
        Some(cors) => router.layer(cors),
        None => router,
    };
    router.with_state(state)
}

fn cors(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    let origins: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();
    Some(
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([Method::GET, Method::PUT, Method::POST, Method::DELETE])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(Duration::from_secs(600)),
    )
}

/// The API only returns JSON, so nothing it sends may run, load or be framed.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; frame-ancestors 'none'";

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

/// Stops other web pages from driving the API through the visitor's browser.
///
/// A request with an `Origin` must come from the API's own origin or one in
/// `api.cors_origins`, which blocks cross-site form posts (CORS alone only
/// hides the response, it does not stop the request). Without credentials
/// configured, the `Host` must also be an IP address or `localhost`: a page on
/// a hostile domain that it re-points at 127.0.0.1 (DNS rebinding) still
/// sends its own name as the host.
async fn guard_browser(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    if !state.auth.required() && !host.is_some_and(is_ip_or_localhost) {
        return (
            StatusCode::FORBIDDEN,
            "set up sign-in (api.users or api.tokens) to use a hostname",
        )
            .into_response();
    }
    if !allowed_origin(headers, host, &state.cors_origins) {
        return (StatusCode::FORBIDDEN, "cross-origin request").into_response();
    }
    next.run(request).await
}

fn allowed_origin(headers: &HeaderMap, host: Option<&str>, allowed: &[String]) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let origin = origin.to_str().unwrap_or_default();
    if allowed.iter().any(|allowed| allowed == origin) {
        return true;
    }
    let authority = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"));
    authority.is_some() && authority == host
}

/// Whether a `Host` header value, with or without a port, names an IP
/// address or `localhost`.
fn is_ip_or_localhost(host: &str) -> bool {
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or(rest, |(ip, _)| ip),
        None => host.rsplit_once(':').map_or(host, |(name, _)| name),
    };
    name.eq_ignore_ascii_case("localhost") || name.parse::<IpAddr>().is_ok()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Finds who sent the request, for the handlers and the role checks.
async fn authenticate(State(state): State<ApiState>, mut request: Request, next: Next) -> Response {
    match state.auth.authenticate(bearer(request.headers())) {
        Some(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        None => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "missing, invalid or expired credentials",
        )
            .into_response(),
    }
}

async fn authorize_by_method(request: Request, next: Next) -> Response {
    let needed = if request.method().is_safe() {
        Role::Viewer
    } else {
        Role::Admin
    };
    authorize(needed, request, next).await
}

async fn authorize_admin(request: Request, next: Next) -> Response {
    authorize(Role::Admin, request, next).await
}

async fn authorize(needed: Role, request: Request, next: Next) -> Response {
    let role = request.extensions().get::<Principal>().map(|p| p.role);
    if role.is_some_and(|role| role >= needed) {
        next.run(request).await
    } else {
        (StatusCode::FORBIDDEN, "this needs the admin role").into_response()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    name: String,
    password: String,
}

#[derive(Serialize)]
struct Me {
    name: String,
    role: Role,
    via: Via,
}

impl From<&Principal> for Me {
    fn from(principal: &Principal) -> Self {
        Self {
            name: principal.name.to_string(),
            role: principal.role,
            via: principal.via,
        }
    }
}

#[derive(Serialize)]
struct LoginResponse {
    /// Send as `Authorization: Bearer <token>`.
    token: String,
    user: Me,
    /// The longest the session can last. It ends sooner when unused for
    /// `api.session_idle_secs`.
    expires_in_secs: u64,
}

async fn login(
    State(state): State<ApiState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(body): Json<LoginRequest>,
) -> Response {
    let address = peer.map(|Extension(ConnectInfo(addr))| addr.ip());
    match state.auth.login(&body.name, &body.password, address).await {
        Ok(login) => Json(LoginResponse {
            token: login.token,
            user: Me::from(&login.principal),
            expires_in_secs: login.expires_in.as_secs(),
        })
        .into_response(),
        Err(LoginError::Invalid) => {
            (StatusCode::UNAUTHORIZED, "wrong name or password").into_response()
        }
        Err(LoginError::Limited(wait)) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, (wait.as_secs() + 1).to_string())],
            "too many failed sign-ins; try again later",
        )
            .into_response(),
        Err(LoginError::NoAccounts) => (
            StatusCode::NOT_FOUND,
            "this server has no user accounts; use an API token",
        )
            .into_response(),
    }
}

async fn logout(State(state): State<ApiState>, headers: HeaderMap) -> StatusCode {
    if let Some(bearer) = bearer(&headers) {
        state.auth.logout(bearer);
    }
    StatusCode::NO_CONTENT
}

async fn me(Extension(principal): Extension<Principal>) -> Json<Me> {
    Json(Me::from(&principal))
}

async fn get_audit(State(state): State<ApiState>) -> Json<Vec<Event>> {
    Json(state.auth.audit().recent())
}

#[derive(Deserialize)]
struct TopParams {
    top: Option<usize>,
}

async fn get_stats(
    State(state): State<ApiState>,
    Query(params): Query<TopParams>,
) -> Json<Snapshot> {
    let top = params.top.unwrap_or(DEFAULT_TOP).min(MAX_TOP);
    Json(state.stats.snapshot(top))
}

async fn reset_stats(
    State(state): State<ApiState>,
    Extension(by): Extension<Principal>,
) -> StatusCode {
    state.stats.reset();
    state
        .auth
        .audit()
        .record(&by.name, "stats reset", String::new());
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
struct BlockingStatus {
    /// Whether queries are being blocked right now.
    active: bool,
    /// Seconds left on a pause, if blocking is paused.
    paused_for_secs: Option<u64>,
    blocked_domains: usize,
    allowed_domains: usize,
    /// Unix time of the last list reload.
    last_reload: Option<u64>,
    sources: Vec<SourceStatus>,
}

fn blocking_status(blocklist: &Blocklist) -> BlockingStatus {
    let rules = blocklist.rules();
    BlockingStatus {
        active: blocklist.enabled(),
        paused_for_secs: blocklist.paused_for().map(|d| d.as_secs()),
        blocked_domains: rules.blocked.len(),
        allowed_domains: rules.allowed.len(),
        last_reload: blocklist
            .last_reload()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
        sources: blocklist.sources().to_vec(),
    }
}

async fn get_blocking(State(state): State<ApiState>) -> Json<BlockingStatus> {
    Json(blocking_status(&state.blocklist))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetBlocking {
    enabled: bool,
    /// With `enabled: false`, turn blocking back on after this many seconds.
    pause_secs: Option<u64>,
}

async fn set_blocking(
    State(state): State<ApiState>,
    Extension(by): Extension<Principal>,
    Json(body): Json<SetBlocking>,
) -> Result<Json<BlockingStatus>, (StatusCode, &'static str)> {
    match (body.enabled, body.pause_secs) {
        (true, Some(_)) => {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "pause_secs only applies when enabled is false",
            ));
        }
        (false, Some(secs)) => state.blocklist.pause(Duration::from_secs(secs)),
        (enabled, None) => state.blocklist.set_enabled(enabled),
    }
    let detail = match (body.enabled, body.pause_secs) {
        (true, _) => "on".to_owned(),
        (false, Some(secs)) => format!("paused for {secs} s"),
        (false, None) => "off".to_owned(),
    };
    state
        .auth
        .audit()
        .record(&by.name, "blocking changed", detail);
    Ok(Json(blocking_status(&state.blocklist)))
}

async fn reload_blocking(
    State(state): State<ApiState>,
    Extension(by): Extension<Principal>,
) -> Json<BlockingStatus> {
    state
        .auth
        .audit()
        .record(&by.name, "blocklists reloaded", String::new());
    state.blocklist.reload().await;
    Json(blocking_status(&state.blocklist))
}

#[derive(Deserialize)]
struct CheckParams {
    name: String,
    /// Check with the rules of the client group this address belongs to.
    client: Option<IpAddr>,
}

#[derive(Serialize)]
struct CheckResult {
    name: String,
    /// Whether the rules match, regardless of whether blocking is active.
    blocked: bool,
    rule: Option<String>,
    /// The client group whose rules applied, if any.
    client: Option<String>,
}

async fn check(
    State(state): State<ApiState>,
    Query(params): Query<CheckParams>,
) -> Json<CheckResult> {
    let name = params
        .name
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let group = params
        .client
        .and_then(|ip| state.blocklist.clients().lookup(ip))
        .map(|g| g.name.clone());
    let rule = state
        .blocklist
        .blocked_by(&name, params.client)
        .map(|(rule, _)| rule);
    Json(CheckResult {
        blocked: rule.is_some(),
        name,
        rule,
        client: group,
    })
}

#[derive(Serialize)]
struct ClientsStatus {
    /// Local time in the schedules' time zone, `YYYY-MM-DDTHH:MM`.
    now: String,
    groups: Vec<ClientStatus>,
}

async fn get_clients(State(state): State<ApiState>) -> Json<ClientsStatus> {
    let clients = state.blocklist.clients();
    let now = clients.now();
    Json(ClientsStatus {
        now: now.strftime("%Y-%m-%dT%H:%M").to_string(),
        groups: clients.groups().iter().map(|g| g.status(now)).collect(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetClient {
    /// Turn the group's own rules off for this many seconds. 0 resumes them.
    pause_secs: u64,
}

async fn set_client(
    State(state): State<ApiState>,
    Extension(by): Extension<Principal>,
    Path(name): Path<String>,
    Json(body): Json<SetClient>,
) -> Result<Json<ClientStatus>, (StatusCode, &'static str)> {
    let clients = state.blocklist.clients();
    let group = clients
        .get(&name)
        .ok_or((StatusCode::NOT_FOUND, "no client group with that name"))?;
    group.pause(Duration::from_secs(body.pause_secs));
    let detail = match body.pause_secs {
        0 => format!("{name} resumed"),
        secs => format!("{name} paused for {secs} s"),
    };
    state
        .auth
        .audit()
        .record(&by.name, "client group changed", detail);
    Ok(Json(group.status(clients.now())))
}

#[derive(Serialize)]
struct CacheStatus {
    entries: u64,
}

async fn get_cache(State(state): State<ApiState>) -> Json<CacheStatus> {
    Json(CacheStatus {
        entries: state.cache.len(),
    })
}

async fn clear_cache(
    State(state): State<ApiState>,
    Extension(by): Extension<Principal>,
) -> StatusCode {
    state.cache.clear();
    state
        .auth
        .audit()
        .record(&by.name, "cache cleared", String::new());
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_ip_hosts() {
        for host in [
            "127.0.0.1:8053",
            "192.168.1.2",
            "[::1]:8053",
            "localhost:8053",
            "LOCALHOST",
        ] {
            assert!(is_ip_or_localhost(host), "{host}");
        }
        for host in ["evil.example:8053", "dns.lan", "127.0.0.1.nip.io", ""] {
            assert!(!is_ip_or_localhost(host), "{host}");
        }
    }

    #[test]
    fn compares_origins() {
        let with = |origin: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            headers
        };
        let host = Some("127.0.0.1:8053");
        let allowed = ["http://localhost:8080".to_string()];
        assert!(allowed_origin(&HeaderMap::new(), host, &[]));
        assert!(allowed_origin(&with("http://127.0.0.1:8053"), host, &[]));
        assert!(allowed_origin(
            &with("http://localhost:8080"),
            host,
            &allowed
        ));
        assert!(!allowed_origin(&with("http://localhost:8080"), host, &[]));
        assert!(!allowed_origin(
            &with("http://evil.example"),
            host,
            &allowed
        ));
        assert!(!allowed_origin(&with("null"), host, &allowed));
    }
}
