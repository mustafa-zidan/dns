# Performance

`bench/compare.sh` measures how many queries per second a server answers, and how fast. It can run two versions of hushdns side by side, and Technitium DNS Server under the same load. Every version tag runs it in CI against the tag before it, so a release that gets slower shows up in its benchmark run.

## Baseline: hushdns 0.0.1 and Technitium 15.6.2

| Scenario | Queries |
|---|---|
| cached | A thousand names, all in the cache after a warm-up pass |
| blocked | Names from a 100,000-domain blocklist, half of them as subdomains of a listed name |
| forwarded | A new name every query, so every one goes upstream |
| mixed | 60% cached, 25% blocked, 15% forwarded, roughly a home network |

| Scenario | Target | Queries/s | p50 | p99 | Timeouts | Peak memory |
|---|---|---:|---:|---:|---:|---:|
| cached | hushdns v0.0.1 | 161393 | 380 µs | 793 µs | 0 | 45.3 MiB |
| cached | Technitium 15.6.2 | 87196 (-46.0%) | 491 µs (+29.2%) | 2689 µs (+239.1%) | 0 | 261.9 MiB |
| blocked | hushdns v0.0.1 | 186403 | 325 µs | 658 µs | 0 | 45.3 MiB |
| blocked | Technitium 15.6.2 | 78066 (-58.1%) | 717 µs (+120.6%) | 2407 µs (+265.8%) | 0 | 417.6 MiB |
| forwarded | hushdns v0.0.1 | 23005 | 2697 µs | 5025 µs | 0 | 51.0 MiB |
| forwarded | Technitium 15.6.2 | 12058 (-47.6%) | 3734 µs (+38.5%) | 50.8 ms (+910.7%) | 0 | 856.0 MiB |
| mixed | hushdns v0.0.1 | 77613 | 659 µs | 2656 µs | 0 | 51.3 MiB |
| mixed | Technitium 15.6.2 | 37884 (-51.2%) | 428 µs (-35.1%) | 13.8 ms (+418.6%) | 0 | 1430.5 MiB |

Percent changes are against hushdns 0.0.1. Higher queries per second is better; lower latency is better.

This ran on a 4-CPU Intel Xeon at 2.10 GHz, with the server on two CPUs and the load generator and upstream on the other two. There were 64 queries in flight over UDP, each run lasted 15 seconds after a 5-second warm-up, and each figure is the median of three runs. Peak memory is the highest resident size the server reached up to the end of that scenario. The scenarios run in the order shown, so it only grows.

On this machine, hushdns answers about twice as many queries as Technitium in every scenario. Its p99 latency is 3 to 10 times lower, and it uses 45 to 51 MiB of memory where Technitium grows from 260 MiB to 1.4 GiB. The one figure where Technitium comes out ahead is the median latency of the mixed scenario. With hushdns, each forwarded query holds up a worker for longer, so the cached and blocked answers queued behind it wait a little longer. The forwarded scenario is where hushdns has the most room to improve. That work is tracked in [#21](https://github.com/mustafa-zidan/hushdns/issues/21).

## How it's measured

- Both servers forward to the same local fake upstream, which answers every query at once, so the upstream is never the bottleneck. They load the same blocklist and answer blocked names with NXDOMAIN.
- Technitium is configured to match hushdns: one plain UDP forwarder, DNSSEC validation off (hushdns doesn't validate, and the fake upstream signs nothing), and no per-client rate limit for the load generator. It runs in Docker with host networking, on the same CPUs hushdns gets.
- The load generator is closed-loop. Each of the 64 workers sends a query and waits for its answer before sending the next one. Queries per second is answers received, divided by the run's length.
- Each server first gets a warm-up of mixed load that isn't measured. This fills the caches and lets .NET compile Technitium's hot paths.
- Default settings otherwise, including a 10,000-entry cache for both.

Numbers from shared CI runners move by a few percent from run to run, so treat smaller differences as noise.

## Running it yourself

You need Rust, and Docker for Technitium. Use a machine with at least 4 CPUs, so the server and the load generator get CPUs of their own.

```sh
# Two versions of hushdns. The first is the baseline.
bench/compare.sh v0.0.1 HEAD

# hushdns and Technitium.
bench/compare.sh --technitium v0.0.1

# Shorter runs while you iterate.
bench/compare.sh --duration 5 --runs 1 v0.0.1 HEAD
```

The script builds each ref in its own git worktree, then prints a Markdown table like the one above. The raw results are saved as JSON. `bench/compare.sh --help` lists the options.

In CI, the **Benchmark** workflow runs on every version tag. To compare any two refs, run it by hand from the Actions tab. The report appears in the run's summary, and the raw results are attached to the run.
