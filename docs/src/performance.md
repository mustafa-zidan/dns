# Performance

`bench/compare.sh` measures how many queries per second a server answers, and how fast. It can run two versions of hushdns side by side, and Technitium DNS Server under the same load. Every version tag runs it in CI against the tag before it, so a release that gets slower shows up in its benchmark run.

## Scenarios

| Scenario | Queries |
|---|---|
| cached | A thousand names, all in the cache after a warm-up pass |
| blocked | Names from a 100,000-domain blocklist, half of them as subdomains of a listed name |
| forwarded | A new name every query, so every one goes upstream |
| mixed | 60% cached, 25% blocked, 15% forwarded, roughly a home network |

## hushdns 0.0.1, 0.0.2 and Technitium 15.6.2

| Scenario | Target | Queries/s | p50 | p99 | Timeouts | Peak memory |
|---|---|---:|---:|---:|---:|---:|
| cached | hushdns 0.0.1 | 161770 | 381 µs | 784 µs | 0 | 45.8 MiB |
| cached | hushdns 0.0.2 | 216574 (+33.9%) | 288 µs (-24.4%) | 597 µs (-23.9%) | 0 | 51.0 MiB |
| cached | Technitium 15.6.2 | 82393 (-49.1%) | 722 µs (+89.5%) | 2257 µs (+187.9%) | 0 | 259.7 MiB |
| blocked | hushdns 0.0.1 | 187680 | 326 µs | 669 µs | 0 | 45.8 MiB |
| blocked | hushdns 0.0.2 | 244280 (+30.2%) | 257 µs (-21.2%) | 485 µs (-27.5%) | 0 | 51.0 MiB |
| blocked | Technitium 15.6.2 | 74526 (-60.3%) | 732 µs (+124.5%) | 2875 µs (+329.7%) | 0 | 376.7 MiB |
| forwarded | hushdns 0.0.1 | 30107 | 2064 µs | 3824 µs | 0 | 51.7 MiB |
| forwarded | hushdns 0.0.2 | 44985 (+49.4%) | 1373 µs (-33.5%) | 2629 µs (-31.2%) | 0 | 51.0 MiB |
| forwarded | Technitium 15.6.2 | 11993 (-60.2%) | 3510 µs (+70.1%) | 56.2 ms (+1368.8%) | 0 | 1104.9 MiB |
| mixed | hushdns 0.0.1 | 88028 | 590 µs | 2332 µs | 0 | 51.9 MiB |
| mixed | hushdns 0.0.2 | 125730 (+42.8%) | 421 µs (-28.6%) | 1626 µs (-30.3%) | 0 | 51.0 MiB |
| mixed | Technitium 15.6.2 | 35259 (-59.9%) | 461 µs (-21.9%) | 14.8 ms (+533.9%) | 0 | 1133.4 MiB |

Percent changes are against hushdns 0.0.1. Higher queries per second is better; lower latency is better.

This ran on a 4-CPU Intel Xeon at 2.10 GHz, with the server on two CPUs and the load generator and upstream on the other two. There were 64 queries in flight over UDP, each run lasted 15 seconds after a 5-second warm-up, and each figure is the median of three runs. Peak memory is the highest resident size the server reached up to the end of that scenario. The scenarios run in the order shown, so it only grows.

In 0.0.2, hushdns answers 30% to 50% more queries, with p99 latency 24% to 31% lower, in every scenario. Against Technitium on this machine, that is 2.6 to 3.8 times the queries, with p99 latency 4 to 21 times lower, in a fifth of the memory or less.

### What changed in 0.0.2

Each change was profiled with `perf` under this benchmark and kept only if it measured better.

- **Each query is parsed once.** The UDP and encrypted transports parsed every query a second time to find its payload size and whether it asked for padding. The handler now returns both with the answer.
- **No error is built for queries that succeed.** Resolving created an error up front, in case every upstream failed. With `RUST_BACKTRACE` set, that also captured a stack trace per forwarded query, which took a fifth of the server's time. The error is now built only when a server fails.
- **No zeroed 64 KB buffer per upstream answer.** The receive buffer is left uninitialized, and only the bytes received are read.
- **Built with link-time optimization** and one codegen unit, and **uses mimalloc** in place of the system allocator. Together they added about 30% on cached answers in quick runs. Build with `--no-default-features` to use the system allocator.
- **One UDP socket per worker thread.** On Linux the sockets share the port with `SO_REUSEPORT` and the kernel spreads clients across them, so queries are received in parallel. This added about 7% with two CPUs, and adds more with more.
- **Sharded per-domain counters, hashed with foldhash.** Every query recorded its name under one lock. With four threads that lock alone capped recording at 3.6 million names a second, and sixteen shards reach 16.5 million.
- **Pipelined TCP and DNS-over-TLS.** Each connection answered one query at a time, so a query waiting on an upstream held up every query after it. Queries are now answered as they're ready, up to 32 at a time per connection ([RFC 7766](https://www.rfc-editor.org/rfc/rfc7766#section-6.2.1.1)). The benchmark only measures UDP, so this doesn't show in the table.

### Large blocklists

Blocklist domains are packed end to end in one buffer, and the hash table holds only their positions, so a domain no longer costs its own heap allocation. Lists are also parsed on a blocking thread, so a big list doesn't stall the queries on the worker that loads it. With a 1,000,000-domain list:

| | hushdns 0.0.1 | hushdns 0.0.2 |
|---|---:|---:|
| Time to load the list | 0.75 s | 0.55 s |
| Resident memory after loading | 93 MiB | 72 MiB |
| Peak memory while loading | 135 MiB | 135 MiB |

With mimalloc and the old layout, the same list stayed at 120 MiB, so the packing more than pays for the allocator. Most of the peak is the downloaded list itself, held in memory while it's parsed. Reading lists as a stream would lower it, and is left for later.

## How it's measured

- Both servers forward to the same local fake upstream, which answers every query at once, so the upstream is never the bottleneck. They load the same blocklist and answer blocked names with NXDOMAIN.
- Technitium is configured to match hushdns: one plain UDP forwarder, DNSSEC validation off (hushdns doesn't validate, and the fake upstream signs nothing), and no per-client rate limit for the load generator. It runs in Docker with host networking, on the same CPUs hushdns gets.
- The load generator is closed-loop. Each of the 64 workers sends a query and waits for its answer before sending the next one. Queries per second is answers received, divided by the run's length.
- Each server first gets a warm-up of mixed load that isn't measured. This fills the caches and lets .NET compile Technitium's hot paths.
- Default settings otherwise, including a 10,000-entry cache for both.

- `RUST_BACKTRACE` and `RUST_LIB_BACKTRACE` are unset, as on a default install.

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

Pull requests that change the server are benchmarked against their base branch, with shorter runs, and fail if queries per second drop more than 15% in any scenario (`--max-regression 15`). The limit is loose because shared runners are noisy, so it catches large regressions, not small ones.
