# Blocklists

Blocking is set in the `[blocking]` section:

```toml
[blocking]
enabled = true
mode = "nxdomain"          # or "null_ip" (0.0.0.0 / ::) or "refused"
blocked_ttl = 60
lists = [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
  "/etc/hushdns/my-list.txt",
]
denylist = ["ads.example.com"]
allowlist = ["login.example.com"]
refresh_interval_secs = 86400
```

## Lists

`lists` takes URLs and file paths. Each list is downloaded or read when the server starts, then again every `refresh_interval_secs` (a day by default, 0 turns refreshing off). A list that fails to load is skipped until the next refresh, and its error shows in the dashboard and in `GET /api/blocking`. The other lists still apply.

Three formats are understood, and they can be mixed in one file:

| Format | Example |
|---|---|
| Hosts file | `0.0.0.0 ads.example.com` |
| Plain domain list | `ads.example.com` |
| Adblock-style rules | `||ads.example.com^` to block, `@@||ads.example.com^` to allow |

Comments (`#` and `!`), blank lines and adblock rules that aren't about whole domains are skipped.

A rule blocks the domain and every name under it, so `example.com` also blocks `ads.example.com`.

## Deny and allow lists

`denylist` adds domains of your own, and `allowlist` names domains that are never blocked. Both include subdomains. **The allowlist always wins**, over the lists, the denylist and the adblock rules.

## How blocked names are answered

| `mode` | Answer |
|---|---|
| `nxdomain` (default) | The name doesn't exist |
| `null_ip` | `0.0.0.0` for A queries and `::` for AAAA, with no data for other types |
| `refused` | The server refuses the query |

Blocked answers carry a TTL of `blocked_ttl` seconds, so a device asks again soon after you unblock a name.

## Turning blocking off for a while

The [dashboard](dashboard.md) and the [API](api.md) can turn blocking off, pause it for a few minutes, or reload the lists right away:

```sh
curl -X PUT localhost:8053/api/blocking -H 'content-type: application/json' \
  -d '{"enabled": false, "pause_secs": 300}'
curl -X POST localhost:8053/api/blocking/reload
```

Pausing blocking pauses [per-client rules](clients.md) too.

## Checking a name

`GET /api/check?name=ads.example.com` tells you whether a name is blocked, and by which rule. The dashboard has the same check.
