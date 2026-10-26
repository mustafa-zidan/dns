//! HTTP API for stats and runtime control.
//!
//! | Method | Path                    | What it does                                   |
//! |--------|-------------------------|------------------------------------------------|
//! | GET    | `/api/health`           | Liveness check                                 |
//! | GET    | `/api/stats?top=N`      | Query counters and top domains                 |
//! | DELETE | `/api/stats`            | Reset the counters                             |
//! | GET    | `/api/blocking`         | Blocking state, rule counts, per-list status   |
//! | PUT    | `/api/blocking`         | `{"enabled": bool, "pause_secs": n}`           |
//! | POST   | `/api/blocking/reload`  | Re-download the blocklists now                 |
//! | GET    | `/api/check?name=x`     | Whether a name is blocked, and by which rule   |
//! | GET    | `/api/cache`            | Number of cached answers                       |
//! | DELETE | `/api/cache`            | Empty the cache                                |

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::extract::{Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::blocklist::{Blocklist, SourceStatus, Verdict};
use crate::cache::Cache;
use crate::stats::{Snapshot, Stats};

const DEFAULT_TOP: usize = 10;
const MAX_TOP: usize = 100;

#[derive(Clone)]
pub struct ApiState {
    pub blocklist: Arc<Blocklist>,
    pub cache: Arc<Cache>,
    pub stats: Arc<Stats>,
    pub token: Option<Arc<str>>,
}

/// Binds the API and serves it until the listener fails.
pub async fn serve(listen: SocketAddr, state: ApiState) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding API on {listen}"))?;
    if state.token.is_none() && !listen.ip().is_loopback() {
        warn!(%listen, "the API is reachable from the network without a token; set api.token");
    }
    info!(%listen, "API listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

pub fn router(state: ApiState) -> Router {
    let api = Router::new()
        .route("/stats", get(get_stats).delete(reset_stats))
        .route("/blocking", get(get_blocking).put(set_blocking))
        .route("/blocking/reload", post(reload_blocking))
        .route("/check", get(check))
        .route("/cache", get(get_cache).delete(clear_cache))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));
    Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .nest("/api", api)
        .with_state(state)
}

async fn require_token(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let Some(token) = &state.token else {
        return next.run(request).await;
    };
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(presented) if constant_time_eq(presented.as_bytes(), token.as_bytes()) => {
            next.run(request).await
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "missing or invalid token",
        )
            .into_response(),
    }
}

/// Compares without returning early, so response timing does not reveal how
/// much of the token was right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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

async fn reset_stats(State(state): State<ApiState>) -> StatusCode {
    state.stats.reset();
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
    info!(
        enabled = body.enabled,
        pause_secs = body.pause_secs,
        "blocking changed through the API"
    );
    Ok(Json(blocking_status(&state.blocklist)))
}

async fn reload_blocking(State(state): State<ApiState>) -> Json<BlockingStatus> {
    state.blocklist.reload().await;
    Json(blocking_status(&state.blocklist))
}

#[derive(Deserialize)]
struct CheckParams {
    name: String,
}

#[derive(Serialize)]
struct CheckResult {
    name: String,
    /// Whether the rules match, regardless of whether blocking is active.
    blocked: bool,
    rule: Option<String>,
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
    let rules = state.blocklist.rules();
    let rule = match rules.check(&name) {
        Verdict::Blocked(rule) => Some(rule.to_string()),
        Verdict::Allowed => None,
    };
    Json(CheckResult {
        blocked: rule.is_some(),
        name,
        rule,
    })
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

async fn clear_cache(State(state): State<ApiState>) -> StatusCode {
    state.cache.clear();
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_tokens() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret2"));
    }
}
