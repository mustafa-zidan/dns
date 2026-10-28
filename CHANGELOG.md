# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.0.2] - 2026-10-28

### Added

- A benchmark (`bench/compare.sh`) that compares two versions of hushdns, and Technitium DNS Server, under the same cached, blocked, forwarded and mixed load. It runs in CI for every version tag against the previous one, and pull requests that change the server fail if throughput drops more than 15%. The docs have a Performance page with the numbers.

### Changed

- 30% to 50% more queries per second than 0.0.1 in every benchmark scenario, with p99 latency 24% to 31% lower. Each query is parsed once, the binary is built with link-time optimization and uses mimalloc, UDP is received on one socket per worker thread, and per-domain counters no longer share one lock.
- TCP and DNS-over-TLS connections answer pipelined queries as they're ready, instead of one at a time.
- Blocklists use less memory and load faster: a 1,000,000-domain list takes 72 MiB instead of 93 MiB and loads in 0.55 s instead of 0.75 s. Parsing no longer holds up queries.

## [0.0.1] - 2026-10-28

The first release.

### Added

- The hushdns logo, a pixel block with an h, in the dashboard header, as its favicon and on the docs site.
- User docs with dashboard screenshots, published at the project's GitHub Pages site on each release.
- Linux binaries for `x86_64` and `aarch64` with every release, with SHA-256 checksums.
- UDP and TCP DNS server forwarding to upstream resolvers with failover and a TTL-aware cache.
- Blocklists from URLs or files (hosts files, plain domain lists, adblock `||domain^` rules), refreshed on a schedule, with inline deny and allow lists.
- DNS-over-TLS and DNS-over-HTTPS upstreams, bootstrap resolution for their hostnames, and EDNS(0) padding of encrypted queries.
- Helm chart (`charts/hushdns`) for the server and dashboard, configured entirely through values, published to `oci://ghcr.io/<owner>/charts/hushdns` on version tags. `hushdns --check-config` validates a config file without starting the server.
- `HUSHDNS_LOG_FORMAT=json` for one JSON object per log line, and an opt-in `hushdns::query` event per query with fixed field names (`name`, `qtype`, `outcome`, `rcode`, `rule`, `client_ip`, `client_group`, `transport`, `duration_ms`). Other log fields now use the same names throughout.
- The dashboard shows client groups with their rules, lists and open schedules, can pause one group, and checks a domain for a given client address.
- Per-client blocklists (`lists`) and weekly schedules (`[[clients.schedules]]`) that block everything or a denylist during a time window, in `server.timezone`. `GET /api/clients` shows each group, and `PUT /api/clients/<name>` pauses one group's rules.
- Per-client rules (`[[clients]]`): groups of addresses and networks with their own denylist and allowlist, optionally skipping the shared blocklists. `/api/check` takes a `client` address.
- DNS-over-TLS and DNS-over-HTTPS listeners for clients (`[tls]`), with HTTP/2, GET and POST, response padding for padded queries, and certificate reload on renewal.
- Upstream queries over TCP, DNS-over-TLS and DNS-over-HTTPS retry once on a fresh connection when the server hangs up before answering.
- HTTP API (`127.0.0.1:8053`, optional bearer token) with query stats, top queried and blocked domains, a blocking on/off/pause switch, blocklist reload and status, a name checker, and cache controls.
- Web dashboard (`web/`, image `ghcr.io/mustafa-zidan/hushdns-dashboard`) for stats, top domains, blocking controls, list status and a domain checker, plus a compose example that runs it with the server. Its dependencies are managed with pnpm under a strict supply-chain policy (7-day minimum release age, no trust downgrades, no exotic subdependencies, no unapproved install scripts).
- `api.cors_origins` to let the dashboard, or other web apps, call the API from a browser. The API now also rejects cross-site requests from other origins and, without a token, DNS-rebinding requests.
- Multi-arch Docker image (`linux/amd64`, `linux/arm64`) on distroless Debian 13, published to GitHub Container Registry.

[Unreleased]: https://github.com/mustafa-zidan/hushdns/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/mustafa-zidan/hushdns/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/mustafa-zidan/hushdns/releases/tag/v0.0.1
