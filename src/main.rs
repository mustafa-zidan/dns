use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use dns::blocklist::Blocklist;
use dns::cache::Cache;
use dns::config::Config;
use dns::handler::Handler;
use dns::server;
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
    if config.blocking.enabled {
        blocklist.spawn_refresh();
    }

    let upstreams = Upstreams::new(config.upstream.servers.clone(), config.upstream.timeout());
    info!(servers = ?config.upstream.servers.iter().map(ToString::to_string).collect::<Vec<_>>(), "upstreams");
    let handler = Arc::new(Handler::new(
        blocklist,
        &config.blocking,
        Cache::new(config.cache.clone()),
        upstreams,
    ));

    tokio::select! {
        result = server::serve(
            &config.server.listen,
            handler,
            Duration::from_secs(config.server.tcp_idle_timeout_secs),
        ) => result,
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
