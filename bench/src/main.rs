//! Benchmarks a DNS server: a fake upstream that answers everything, a
//! closed-loop UDP load generator for a few query mixes, and a report that
//! compares result files. `bench/compare.sh` drives it.

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

#[derive(Parser)]
#[command(about = "Benchmark tools for hushdns")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Answer every A query with 192.0.2.1 and every other type with no data.
    Upstream {
        #[arg(long, default_value = "127.0.0.1:5300")]
        listen: SocketAddr,
        #[arg(long, default_value_t = 4)]
        tasks: usize,
    },
    /// Write a blocklist of `count` domains, one per line.
    Blocklist {
        #[arg(long, default_value_t = 100_000)]
        count: usize,
        out: PathBuf,
    },
    /// Query a name until the server answers with the expected response code.
    Probe {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long)]
        name: String,
        /// 0 is NOERROR, 3 is NXDOMAIN.
        #[arg(long)]
        rcode: u8,
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
    },
    /// Send queries for `duration_secs` and write the result as JSON.
    Load(LoadArgs),
    /// Print a Markdown comparison of result files.
    Report {
        /// The target the others are compared against.
        #[arg(long)]
        baseline: String,
        files: Vec<PathBuf>,
    },
}

#[derive(clap::Args)]
struct LoadArgs {
    #[arg(long)]
    server: SocketAddr,
    #[arg(long, value_enum)]
    scenario: Scenario,
    /// A label for the server under test, such as "hushdns v0.0.1".
    #[arg(long)]
    target: String,
    #[arg(long, default_value_t = 15)]
    duration_secs: u64,
    /// Queries in flight at once.
    #[arg(long, default_value_t = 64)]
    concurrency: usize,
    /// Domains in the blocklist the server loaded, from `blocklist --count`.
    #[arg(long, default_value_t = 100_000)]
    blocklist_count: usize,
    /// Read the server's peak memory from /proc/<pid>/status when done.
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
enum Scenario {
    /// A thousand names, all in the cache after a warm-up pass.
    Cached,
    /// Names from the blocklist, half of them as subdomains.
    Blocked,
    /// A new name every query, so every one goes upstream.
    Forwarded,
    /// 60% cached, 25% blocked, 15% forwarded: a rough home network.
    Mixed,
}

impl Scenario {
    fn label(self) -> &'static str {
        match self {
            Scenario::Cached => "cached",
            Scenario::Blocked => "blocked",
            Scenario::Forwarded => "forwarded",
            Scenario::Mixed => "mixed",
        }
    }
}

const CACHED_NAMES: u64 = 1000;

#[derive(Serialize, Deserialize)]
struct Outcome {
    target: String,
    scenario: Scenario,
    concurrency: usize,
    duration_secs: f64,
    queries: u64,
    qps: f64,
    p50_us: u64,
    p90_us: u64,
    p99_us: u64,
    max_us: u64,
    timeouts: u64,
    errors: u64,
    peak_rss_kb: Option<u64>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Blocklist { count, out } => {
            let mut text = String::with_capacity(count * 20);
            for i in 0..count {
                text.push_str(&blocked_name(i as u64));
                text.push('\n');
            }
            fs::write(&out, text).with_context(|| format!("writing {}", out.display()))
        }
        Command::Report { baseline, files } => report(&baseline, &files),
        command => tokio::runtime::Runtime::new()?.block_on(run_async(command)),
    }
}

async fn run_async(command: Command) -> Result<()> {
    match command {
        Command::Upstream { listen, tasks } => upstream(listen, tasks).await,
        Command::Probe {
            server,
            name,
            rcode,
            timeout_secs,
        } => probe(server, &name, rcode, Duration::from_secs(timeout_secs)).await,
        Command::Load(args) => load(args).await,
        Command::Blocklist { .. } | Command::Report { .. } => unreachable!(),
    }
}

fn blocked_name(i: u64) -> String {
    format!("ads{i}.tracker{}.hushbench", i % 97)
}

/// A small, fast PRNG; the load only needs names spread evenly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Builds a recursive A query for `name` with the given ID.
fn query(id: u16, name: &str, buf: &mut Vec<u8>) {
    buf.clear();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.extend_from_slice(&[0, 0, 1, 0, 1]);
}

async fn upstream(listen: SocketAddr, tasks: usize) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(listen).await?);
    eprintln!("upstream listening on {listen}");
    for _ in 0..tasks.max(1) {
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let mut out = Vec::with_capacity(512);
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                if let Some(answer) = answer(&buf[..len], &mut out) {
                    let _ = socket.send_to(answer, peer).await;
                }
            }
        });
    }
    // The tasks run until the process is stopped.
    std::future::pending().await
}

/// Answers a query in `out`, copying its question. Ignores EDNS and anything
/// after the question.
fn answer<'a>(query: &[u8], out: &'a mut Vec<u8>) -> Option<&'a [u8]> {
    if query.len() < 12 {
        return None;
    }
    let mut end = 12;
    while *query.get(end)? != 0 {
        end += usize::from(query[end]) + 1;
    }
    let qtype = u16::from_be_bytes([*query.get(end + 1)?, *query.get(end + 2)?]);
    let question = query.get(12..end + 5)?;
    let rd = query[2] & 0x01;
    out.clear();
    out.extend_from_slice(&query[..2]);
    out.extend_from_slice(&[0x80 | rd, 0x80, 0, 1, 0, u8::from(qtype == 1), 0, 0, 0, 0]);
    out.extend_from_slice(question);
    if qtype == 1 {
        // Name pointer to the question, A, IN, TTL 3600, 192.0.2.1.
        out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 192, 0, 2, 1]);
    }
    Some(out)
}

async fn probe(server: SocketAddr, name: &str, rcode: u8, timeout: Duration) -> Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(server).await?;
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::new();
    let mut resp = [0u8; 1500];
    let mut last = None;
    while Instant::now() < deadline {
        query(0x4242, name, &mut buf);
        socket.send(&buf).await?;
        if let Ok(Ok(len)) =
            tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut resp)).await
            && len >= 4
        {
            let got = resp[3] & 0x0f;
            if got == rcode {
                return Ok(());
            }
            last = Some(got);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!("{server} never answered {name} with rcode {rcode} (last: {last:?})")
}

struct Picker {
    scenario: Scenario,
    blocklist: u64,
    rng: Rng,
    worker: u64,
    counter: u64,
}

impl Picker {
    fn name(&mut self) -> String {
        let kind = match self.scenario {
            Scenario::Mixed => match self.rng.next() % 100 {
                0..60 => Scenario::Cached,
                60..85 => Scenario::Blocked,
                _ => Scenario::Forwarded,
            },
            other => other,
        };
        match kind {
            Scenario::Cached => format!("www{}.cached.hushbench", self.rng.next() % CACHED_NAMES),
            Scenario::Blocked => {
                let r = self.rng.next();
                let name = blocked_name(r % self.blocklist);
                if r & (1 << 40) == 0 {
                    name
                } else {
                    format!("cdn.{name}")
                }
            }
            _ => {
                self.counter += 1;
                format!("q{}-{}.forwarded.hushbench", self.worker, self.counter)
            }
        }
    }
}

async fn load(args: LoadArgs) -> Result<()> {
    if matches!(args.scenario, Scenario::Cached | Scenario::Mixed) {
        warm_cache(args.server).await?;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let timeouts = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    // Each run gets its own prefix for forwarded names, so a second run can't
    // hit names the first one cached.
    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos() as u64;
    let start = Instant::now();
    let mut handles = Vec::new();
    for worker in 0..args.concurrency {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.connect(args.server).await?;
        let (stop, timeouts, errors) = (stop.clone(), timeouts.clone(), errors.clone());
        let mut picker = Picker {
            scenario: args.scenario,
            blocklist: args.blocklist_count.max(1) as u64,
            rng: Rng(run_id ^ (worker as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
            worker: (run_id % 1_000_000) * 1000 + worker as u64,
            counter: 0,
        };
        handles.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(1 << 16);
            let mut buf = Vec::with_capacity(128);
            let mut resp = [0u8; 1500];
            let mut id: u16 = worker as u16;
            while !stop.load(Ordering::Relaxed) {
                id = id.wrapping_add(1);
                query(id, &picker.name(), &mut buf);
                let sent = Instant::now();
                if socket.send(&buf).await.is_err() {
                    errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let deadline = sent + Duration::from_secs(2);
                loop {
                    match tokio::time::timeout_at(deadline.into(), socket.recv(&mut resp)).await {
                        // A late answer to an earlier, timed-out query: keep waiting.
                        Ok(Ok(len)) if len >= 2 && resp[..2] != id.to_be_bytes() => continue,
                        Ok(Ok(len)) => {
                            if len < 12 || resp[3] & 0x0f == 2 {
                                errors.fetch_add(1, Ordering::Relaxed);
                            }
                            latencies.push(sent.elapsed().as_micros() as u64);
                        }
                        Ok(Err(_)) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            timeouts.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    break;
                }
            }
            latencies
        }));
    }
    tokio::time::sleep(Duration::from_secs(args.duration_secs)).await;
    stop.store(true, Ordering::Relaxed);
    let mut latencies = Vec::new();
    for handle in handles {
        latencies.extend(handle.await?);
    }
    let elapsed = start.elapsed().as_secs_f64();
    latencies.sort_unstable();
    let pct = |p: f64| {
        latencies
            .get(((latencies.len() as f64 * p) as usize).min(latencies.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0)
    };
    let outcome = Outcome {
        target: args.target,
        scenario: args.scenario,
        concurrency: args.concurrency,
        duration_secs: elapsed,
        queries: latencies.len() as u64,
        qps: latencies.len() as f64 / elapsed,
        p50_us: pct(0.50),
        p90_us: pct(0.90),
        p99_us: pct(0.99),
        max_us: latencies.last().copied().unwrap_or(0),
        timeouts: timeouts.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
        peak_rss_kb: args.pid.and_then(peak_rss_kb),
    };
    eprintln!(
        "{} {}: {:.0} qps, p50 {}µs, p99 {}µs, {} timeouts, {} errors",
        outcome.target,
        args.scenario.label(),
        outcome.qps,
        outcome.p50_us,
        outcome.p99_us,
        outcome.timeouts,
        outcome.errors
    );
    fs::write(&args.out, serde_json::to_string_pretty(&outcome)?)?;
    Ok(())
}

/// Asks for every cached name once, so the cached scenario measures hits.
async fn warm_cache(server: SocketAddr) -> Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(server).await?;
    let mut buf = Vec::new();
    let mut resp = [0u8; 1500];
    for i in 0..CACHED_NAMES {
        query(i as u16, &format!("www{i}.cached.hushbench"), &mut buf);
        socket.send(&buf).await?;
        let _ = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut resp)).await;
    }
    Ok(())
}

fn peak_rss_kb(pid: u32) -> Option<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

fn report(baseline: &str, files: &[PathBuf]) -> Result<()> {
    // For repeated runs of the same target and scenario, keep the median by QPS.
    let mut runs: BTreeMap<(Scenario, String), Vec<Outcome>> = BTreeMap::new();
    let mut targets: Vec<String> = Vec::new();
    for file in files {
        let text =
            fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let outcome: Outcome =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", file.display()))?;
        if !targets.contains(&outcome.target) {
            targets.push(outcome.target.clone());
        }
        runs.entry((outcome.scenario, outcome.target.clone()))
            .or_default()
            .push(outcome);
    }
    if !targets.iter().any(|t| t == baseline) {
        bail!("no results for the baseline {baseline:?}");
    }
    targets.retain(|t| t != baseline);
    targets.insert(0, baseline.to_owned());
    let median = |scenario: Scenario, target: &str| -> Option<&Outcome> {
        let mut list: Vec<&Outcome> = runs.get(&(scenario, target.to_owned()))?.iter().collect();
        list.sort_by(|a, b| a.qps.total_cmp(&b.qps));
        list.get(list.len() / 2).copied()
    };
    let scenarios: Vec<Scenario> = {
        let mut s: Vec<Scenario> = runs.keys().map(|(s, _)| *s).collect();
        s.dedup();
        s
    };

    println!("| Scenario | Target | Queries/s | p50 | p99 | Timeouts | Peak memory |");
    println!("|---|---|---:|---:|---:|---:|---:|");
    for &scenario in &scenarios {
        let base = median(scenario, baseline);
        for target in &targets {
            let Some(o) = median(scenario, target) else {
                continue;
            };
            let vs = |v: f64, b: Option<f64>| match b {
                Some(b) if target != baseline && b > 0.0 => {
                    format!(" ({:+.1}%)", (v - b) / b * 100.0)
                }
                _ => String::new(),
            };
            println!(
                "| {} | {} | {:.0}{} | {}{} | {}{} | {} | {} |",
                scenario.label(),
                target,
                o.qps,
                vs(o.qps, base.map(|b| b.qps)),
                micros(o.p50_us),
                vs(o.p50_us as f64, base.map(|b| b.p50_us as f64)),
                micros(o.p99_us),
                vs(o.p99_us as f64, base.map(|b| b.p99_us as f64)),
                o.timeouts,
                o.peak_rss_kb
                    .map(|kb| format!("{:.1} MiB", kb as f64 / 1024.0))
                    .unwrap_or_else(|| "-".into()),
            );
        }
    }
    println!();
    println!(
        "Percent changes are against {baseline}. For queries per second higher is better; for latency lower is better."
    );
    Ok(())
}

fn micros(us: u64) -> String {
    if us >= 10_000 {
        format!("{:.1} ms", us as f64 / 1000.0)
    } else {
        format!("{us} µs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_a_queries() {
        let mut q = Vec::new();
        query(7, "www1.cached.hushbench", &mut q);
        let mut out = Vec::new();
        let a = answer(&q, &mut out).unwrap();
        assert_eq!(&a[..2], &7u16.to_be_bytes());
        assert_eq!(a[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1);
        assert_eq!(&a[a.len() - 4..], &[192, 0, 2, 1]);
    }

    #[test]
    fn mixed_picks_every_kind() {
        let mut p = Picker {
            scenario: Scenario::Mixed,
            blocklist: 10,
            rng: Rng(42),
            worker: 1,
            counter: 0,
        };
        let names: Vec<String> = (0..1000).map(|_| p.name()).collect();
        assert!(names.iter().any(|n| n.ends_with(".cached.hushbench")));
        assert!(
            names
                .iter()
                .any(|n| n.ends_with(".tracker0.hushbench") || n.contains(".tracker"))
        );
        assert!(names.iter().any(|n| n.ends_with(".forwarded.hushbench")));
    }
}
