# dns

A DNS server written in Rust, focused on ad blocking and privacy. Inspired by [Technitium DNS Server](https://technitium.com/dns/).

It sits between your devices and an upstream resolver. Queries for domains on your blocklists never leave your network; everything else is forwarded upstream and cached.

## Features

- UDP and TCP listeners, with TC-bit truncation for oversized UDP answers.
- Encrypted upstreams: DNS-over-TLS (the default, to Cloudflare and Quad9) and DNS-over-HTTPS, plus plain UDP/TCP. Upstreams are tried in order with failover.
- Upstream hostnames are resolved through configurable bootstrap servers, never through the OS resolver, so the server can safely be its own host's resolver.
- TTL-aware cache with min/max TTL clamping and RFC 2308 negative caching.
- Blocklists from URLs or files, refreshed on a schedule. Hosts files, plain domain lists and adblock-style `||domain^` / `@@||domain^` rules are understood. A rule blocks the domain and all its subdomains.
- Inline denylist and allowlist. The allowlist always wins.
- Blocked names answered with NXDOMAIN, `0.0.0.0` / `::`, or REFUSED.
- Privacy: queries sent upstream get a fresh random ID and source port and carry none of the client's EDNS options, so EDNS Client Subnet never leaks your network. Encrypted queries are padded to 128-byte blocks (RFC 8467) so their size doesn't reveal the name. DoH requests send no User-Agent. Nothing is logged per query unless you turn on debug logging.

## Running with Docker

Images are published to GitHub Container Registry for `linux/amd64` and `linux/arm64`.

```sh
docker run -d --name dns -p 53:53/udp -p 53:53/tcp ghcr.io/mustafa-zidan/dns:latest
```

The image ships with [`config/dns.toml`](config/dns.toml). To use your own, mount it over `/etc/dns/dns.toml`:

```sh
docker run -d --name dns -p 53:53/udp -p 53:53/tcp \
  -v "$PWD/dns.toml:/etc/dns/dns.toml:ro" \
  ghcr.io/mustafa-zidan/dns:latest
```

The container runs as a non-root user.

## Running from source

```sh
cargo run --release -- --config config/dns.toml
```

Binding port 53 usually needs root or `CAP_NET_BIND_SERVICE`; for local testing change `server.listen` to a high port such as `127.0.0.1:5353`.

## Configuration

Everything is in one TOML file, passed with `--config` or the `DNS_CONFIG` environment variable. Every key is optional. See [`config/dns.toml`](config/dns.toml) for all options and their defaults.

Logging is controlled by `DNS_LOG` using [`tracing` filter syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html), for example `DNS_LOG=dns=debug` to see each blocked name and cache hit.

## Roadmap

- HTTP API with query statistics, top blocked domains and a blocking toggle.
- Web dashboard.
- Serving DoH/DoT to clients.
- Per-client rules.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --test live -- --ignored   # queries real public resolvers
```
