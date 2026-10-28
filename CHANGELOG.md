# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- UDP and TCP DNS server forwarding to upstream resolvers with failover and a TTL-aware cache.
- Blocklists from URLs or files (hosts files, plain domain lists, adblock `||domain^` rules), refreshed on a schedule, with inline deny and allow lists.
- DNS-over-TLS and DNS-over-HTTPS upstreams, bootstrap resolution for their hostnames, and EDNS(0) padding of encrypted queries.
- Per-client rules (`[[clients]]`): groups of addresses and networks with their own denylist and allowlist, optionally skipping the shared blocklists. `/api/check` takes a `client` address.
- DNS-over-TLS and DNS-over-HTTPS listeners for clients (`[tls]`), with HTTP/2, GET and POST, response padding for padded queries, and certificate reload on renewal.
- Upstream queries over TCP, DNS-over-TLS and DNS-over-HTTPS retry once on a fresh connection when the server hangs up before answering.
- HTTP API (`127.0.0.1:8053`, optional bearer token) with query stats, top queried and blocked domains, a blocking on/off/pause switch, blocklist reload and status, a name checker, and cache controls.
- Web dashboard (`web/`, image `ghcr.io/mustafa-zidan/dns-dashboard`) for stats, top domains, blocking controls, list status and a domain checker, plus a compose example that runs it with the server. Its dependencies are managed with pnpm under a strict supply-chain policy (7-day minimum release age, no trust downgrades, no exotic subdependencies, no unapproved install scripts).
- `api.cors_origins` to let the dashboard, or other web apps, call the API from a browser. The API now also rejects cross-site requests from other origins and, without a token, DNS-rebinding requests.
- Multi-arch Docker image (`linux/amd64`, `linux/arm64`) on distroless Debian 13, published to GitHub Container Registry.
