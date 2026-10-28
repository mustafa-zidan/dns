# HTTP API

The server has a small JSON API, on `127.0.0.1:8053` by default. The dashboard uses it, and you can script it with `curl`.

```toml
[api]
enabled = true
listen = "127.0.0.1:8053"
token = "change-me"
cors_origins = ["http://localhost:8080"]
```

If `api.token` is set, every request except `/api/health` needs an `Authorization: Bearer <token>` header. Keep the API on loopback unless you set a token.

## Endpoints

| Method | Path | What it does |
|---|---|---|
| GET | `/api/health` | Liveness check |
| GET | `/api/stats?top=10` | Query counts (blocked, cached, forwarded, failed), the blocked share, and the top queried and top blocked domains |
| DELETE | `/api/stats` | Reset the counters |
| GET | `/api/blocking` | Whether blocking is on, rule counts, last reload, and the status of each list |
| PUT | `/api/blocking` | `{"enabled": false}` turns blocking off, `{"enabled": false, "pause_secs": 300}` pauses it for 5 minutes, and `{"enabled": true}` turns it back on |
| POST | `/api/blocking/reload` | Re-download the blocklists now |
| GET | `/api/check?name=ads.example.com` | Whether a name is blocked, and by which rule. Add `&client=<ip>` to apply that client's group |
| GET | `/api/clients` | Client groups with their rule counts, list status, schedules (and whether each is open now), and pause state |
| PUT | `/api/clients/<name>` | `{"pause_secs": 1800}` gives the group only the shared rules for 30 minutes, and `{"pause_secs": 0}` resumes it |
| GET | `/api/cache` | Number of cached answers |
| DELETE | `/api/cache` | Empty the cache |

## Examples

```sh
TOKEN=change-me
curl -s localhost:8053/api/stats -H "authorization: Bearer $TOKEN" | jq
curl -s -X PUT localhost:8053/api/blocking -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"enabled": false, "pause_secs": 300}'
curl -s "localhost:8053/api/check?name=youtube.com&client=192.168.1.20" \
  -H "authorization: Bearer $TOKEN" | jq
```

Stats live in memory only, and reset on restart. Set `stats.top_domains = false` to keep no per-domain counts at all.

## Browsers and other web pages

Other web pages can't drive the API through your browser:

- A request that carries an `Origin` must come from the API's own address, or from one listed in `api.cors_origins`.
- Without a token, the `Host` header must also be an IP address or `localhost`, which stops DNS rebinding. So without a token, reach the API by IP address or `localhost`, not by a hostname.
