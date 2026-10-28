use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use tokio_rustls::TlsAcceptor;
use tracing::info;
use tracing_subscriber::EnvFilter;

use hushdns::api::{self, ApiState};
use hushdns::blocklist::Blocklist;
use hushdns::cache::Cache;
use hushdns::certs::CertStore;
use hushdns::clients::Clients;
use hushdns::config::Config;
use hushdns::doh;
use hushdns::handler::Handler;
use hushdns::server;
use hushdns::stats::Stats;
use hushdns::upstream::Upstreams;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML config file. Built-in defaults are used when omitted.
    #[arg(short, long, env = "HUSHDNS_CONFIG")]
    config: Option<PathBuf>,
    /// Log output: human-readable text, or one JSON object per line for log
    /// search tools.
    #[arg(long, env = "HUSHDNS_LOG_FORMAT", value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
    /// Check the config file and exit, without starting the server.
    #[arg(long)]
    check_config: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let filter = EnvFilter::try_from_env("HUSHDNS_LOG").unwrap_or_else(|_| "info".into());
    let logs = tracing_subscriber::fmt().with_env_filter(filter);
    match args.log_format {
        LogFormat::Text => logs.with_ansi(std::io::stdout().is_terminal()).init(),
        LogFormat::Json => logs
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .init(),
    }

    let config = match &args.config {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };
    if args.check_config {
        Clients::new(&config.clients, config.server.timezone.as_deref())?;
        println!("config is valid");
        return Ok(());
    }

    let clients = Arc::new(Clients::new(
        &config.clients,
        config.server.timezone.as_deref(),
    )?);
    if !clients.is_empty() {
        info!(groups = clients.len(), "per-client rules");
    }
    let blocklist = Arc::new(Blocklist::new(config.blocking.clone())?.with_clients(clients));
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
            cors_origins: config.api.cors_origins.clone().into(),
        };
        api::serve(config.api.listen, state).await
    };

    let idle = Duration::from_secs(config.server.tcp_idle_timeout_secs);
    let certs = match (&config.tls.cert_file, &config.tls.key_file) {
        (Some(cert), Some(key)) if config.tls.enabled() => {
            let certs = CertStore::load(cert, key)?;
            certs.spawn_reload(Duration::from_secs(config.tls.reload_interval_secs));
            Some(certs)
        }
        _ => None,
    };
    let dot = async {
        match &certs {
            Some(certs) if !config.tls.dot_listen.is_empty() => {
                let tls = TlsAcceptor::from(certs.server_config(&[server::DOT_ALPN]));
                server::serve_dot(&config.tls.dot_listen, tls, Arc::clone(&handler), idle).await
            }
            _ => std::future::pending().await,
        }
    };
    let doh = async {
        match &certs {
            Some(certs) if !config.tls.doh_listen.is_empty() => {
                let tls = TlsAcceptor::from(certs.server_config(doh::ALPN));
                let path = &config.tls.doh_path;
                doh::serve(
                    &config.tls.doh_listen,
                    path,
                    tls,
                    Arc::clone(&handler),
                    idle,
                )
                .await
            }
            _ => std::future::pending().await,
        }
    };

    tokio::select! {
        result = server::serve(&config.server.listen, Arc::clone(&handler), idle) => result,
        result = dot => result,
        result = doh => result,
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
