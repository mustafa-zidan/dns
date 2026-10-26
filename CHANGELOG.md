# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- UDP and TCP DNS server forwarding to upstream resolvers with failover and a TTL-aware cache.
- Blocklists from URLs or files (hosts files, plain domain lists, adblock `||domain^` rules), refreshed on a schedule, with inline deny and allow lists.
- DNS-over-TLS and DNS-over-HTTPS upstreams, bootstrap resolution for their hostnames, and EDNS(0) padding of encrypted queries.
- HTTP API (`127.0.0.1:8053`, optional bearer token) with query stats, top queried and blocked domains, a blocking on/off/pause switch, blocklist reload and status, a name checker, and cache controls.
- Web dashboard (`web/`, image `ghcr.io/mustafa-zidan/dns-dashboard`) for stats, top domains, blocking controls, list status and a domain checker, plus a compose example that runs it with the server.
- `api.cors_origins` to let the dashboard, or other web apps, call the API from a browser. The API now also rejects cross-site requests from other origins and, without a token, DNS-rebinding requests.
- Multi-arch Docker image (`linux/amd64`, `linux/arm64`) published to GitHub Container Registry.
