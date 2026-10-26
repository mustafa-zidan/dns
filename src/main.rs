use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use dns::api::{self, ApiState};
use dns::blocklist::Blocklist;
use dns::cache::Cache;
use dns::config::Config;
use dns::handler::Handler;
use dns::server;
use dns::stats::Stats;
use dns::upstream::Upstreams;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML config file. Built-in defaults are used when omitted.
    #[arg(short, long, env = "DNS_CONFIG")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("DNS_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let config = match &args.config {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };

    let blocklist = Arc::new(Blocklist::new(config.blocking.clone())?);
    // Lists load even when blocking starts disabled, so it can be switched on
    // through the API without waiting for a download.
    blocklist.spawn_refresh();

    let upstreams = Upstreams::new(&config.upstream)?;
    info!(servers = ?config.upstream.servers.iter().map(ToString::to_string).collect::<Vec<_>>(), "upstreams");
    let cache = Arc::new(Cache::new(config.cache.clone()));
    let stats = Arc::new(Stats::new(&config.stats));
    let handler = Arc::new(Handler::new(
        Arc::clone(&blocklist),
        &config.blocking,
        Arc::clone(&cache),
        upstreams,
        Arc::clone(&stats),
    ));

    let api = async {
        if !config.api.enabled {
            return std::future::pending().await;
        }
        let state = ApiState {
            blocklist,
            cache,
            stats,
            token: config.api.token.as_deref().map(Arc::from),
        };
        api::serve(config.api.listen, state).await
    };

    tokio::select! {
        result = server::serve(
            &config.server.listen,
            handler,
            Duration::from_secs(config.server.tcp_idle_timeout_secs),
        ) => result,
        result = api => result,
        _ = shutdown_signal() => {
            info!("shutting down");
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("installing SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
