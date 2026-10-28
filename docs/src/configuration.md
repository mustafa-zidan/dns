# Configuration

hushdns reads one TOML file, given with `--config` or the `HUSHDNS_CONFIG` environment variable. Every key is optional. A key you leave out gets its default.

To check a file without starting the server:

```sh
hushdns --check-config --config hushdns.toml
```

## Sections

| Section | What it sets | More |
|---|---|---|
| `[server]` | Listen addresses, TCP idle timeout, time zone for schedules | |
| `[tls]` | DNS-over-TLS and DNS-over-HTTPS for your devices | [Encrypted DNS](encrypted-dns.md#serving-your-devices) |
| `[upstream]` | Upstream resolvers, bootstrap servers, timeout | [Encrypted DNS](encrypted-dns.md#upstreams) |
| `[cache]` | Cache size and TTL limits | |
| `[blocking]` | Lists, deny and allow lists, how blocked names are answered | [Blocklists](blocklists.md) |
| `[[clients]]` | Rules and schedules for some devices | [Per-client rules](clients.md) |
| `[api]` | HTTP API address, token and allowed web origins | [HTTP API](api.md) |
| `[stats]` | Whether to count queries per domain | [Privacy](privacy.md) |

## Environment variables

| Variable | What it does |
|---|---|
| `HUSHDNS_CONFIG` | Path to the config file, if `--config` isn't given |
| `HUSHDNS_LOG` | What to log, in `tracing` filter syntax. Defaults to `info`. See [Logs](logs.md) |
| `HUSHDNS_LOG_FORMAT` | `text` (the default) or `json` |

The dashboard image reads `HUSHDNS_API_URL`, the API address as the browser reaches it.

## The example file

This is the example config shipped in the image, with every option and its default:

```toml
{{#include ../../config/hushdns.toml}}
```
