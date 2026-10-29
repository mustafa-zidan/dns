# HTTP API

The server has a small JSON API, on `127.0.0.1:8053` by default. The dashboard uses it, and you can script it with `curl`.

```toml
[api]
enabled = true
listen = "127.0.0.1:8053"
cors_origins = ["http://localhost:8080"]
```

## Signing in

With no credentials configured, anyone who can reach the API can use it, so keep it on loopback. To open it to your network, set up any of these. Each is sent as an `Authorization: Bearer <secret>` header, and every request except `/api/health` and `/api/login` then needs one.

- **Accounts** in `[[api.users]]`, for people. Signing in with a name and password, from the dashboard or `POST /api/login`, starts a session.
- **API tokens** in `[[api.tokens]]`, for scripts and other programs.
- **`api.token`**, a single admin token, as in earlier versions.

Each account and API token has a role. A **viewer** can read everything: stats, blocking state, lists, client groups and the cache size. An **admin** can also change things: turn blocking off or pause it, pause a client group, reload lists, clear the cache, reset stats, and read the audit log. `role` defaults to `viewer`. `api.token` is always an admin.

```toml
[[api.users]]
name = "admin"
role = "admin"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."

[[api.users]]
name = "family"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."

[[api.tokens]]
name = "home-assistant"
role = "viewer"
hash = "4cb34e79..."
```

The config never holds a password or a token, only a hash of it. Make them with the server binary:

```sh
hushdns hash-password                       # asks for the password, prints the hash
hushdns new-token home-assistant --role viewer  # prints a new token and its [[api.tokens]] entry
```

In Docker, run `docker run --rm -it ghcr.io/mustafa-zidan/hushdns hash-password`. Passwords are hashed with Argon2id, and must be at least 8 characters. Tokens are 256 random bits, so a SHA-256 hash of them is enough.

A session ends when you sign out, after `api.session_idle_secs` without a request (default 8 hours), and after `api.session_max_secs` in any case (default 7 days). Sessions live in the server's memory: a restart ends them all, and with several servers behind one address, a session works only on the one it started on. To remove an account or token, or change a password, edit the config and restart.

After 10 failed sign-ins for an account, or 30 from one address (one IPv6 /64), sign-ins for it are refused for 15 minutes with `429 Too Many Requests`. Behind a reverse proxy every client has the proxy's address, so they share that count. Names that aren't accounts aren't counted against an account, and they take as long to refuse as wrong passwords.

### Audit log

Sign-ins, sign-outs, failed sign-ins and every change made through the API are logged with the target `hushdns::audit`, naming the account or token. The latest 200 are kept in memory for `GET /api/audit` and the dashboard's Recent activity panel.

## Endpoints

| Method | Path | Role | What it does |
|---|---|---|---|
| GET | `/api/health` | none | Liveness check |
| POST | `/api/login` | none | `{"name": "admin", "password": "..."}` starts a session. Answers `{"token", "user", "expires_in_secs"}` |
| POST | `/api/logout` | any | Ends the session the request is sent with |
| GET | `/api/me` | any | `{"name", "role", "via"}` for the credentials sent. `via` is `session`, `token`, or `open` when the API needs no credentials |
| GET | `/api/stats?top=10` | viewer | Query counts (blocked, cached, forwarded, failed), the blocked share, and the top queried and top blocked domains |
| DELETE | `/api/stats` | admin | Reset the counters |
| GET | `/api/blocking` | viewer | Whether blocking is on, rule counts, last reload, and the status of each list |
| PUT | `/api/blocking` | admin | `{"enabled": false}` turns blocking off, `{"enabled": false, "pause_secs": 300}` pauses it for 5 minutes, and `{"enabled": true}` turns it back on |
| POST | `/api/blocking/reload` | admin | Re-download the blocklists now |
| GET | `/api/check?name=ads.example.com` | viewer | Whether a name is blocked, and by which rule. Add `&client=<ip>` to apply that client's group |
| GET | `/api/clients` | viewer | Client groups with their rule counts, list status, schedules (and whether each is open now), and pause state |
| PUT | `/api/clients/<name>` | admin | `{"pause_secs": 1800}` gives the group only the shared rules for 30 minutes, and `{"pause_secs": 0}` resumes it |
| GET | `/api/cache` | viewer | Number of cached answers |
| DELETE | `/api/cache` | admin | Empty the cache |
| GET | `/api/audit` | admin | Recent sign-ins and changes, newest first |

Missing, wrong or expired credentials get `401`, and a viewer asking to change something gets `403`.

## Examples

```sh
TOKEN=hdt_...   # from hushdns new-token, or a session token from /api/login
curl -s localhost:8053/api/stats -H "authorization: Bearer $TOKEN" | jq
curl -s -X PUT localhost:8053/api/blocking -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"enabled": false, "pause_secs": 300}'
curl -s "localhost:8053/api/check?name=youtube.com&client=192.168.1.20" \
  -H "authorization: Bearer $TOKEN" | jq

# Sign in with an account instead
TOKEN=$(curl -s localhost:8053/api/login -H 'content-type: application/json' \
  -d '{"name": "admin", "password": "..."}' | jq -r .token)
```

Stats live in memory only, and reset on restart. Set `stats.top_domains = false` to keep no per-domain counts at all.

## Browsers and other web pages

Other web pages can't drive the API through your browser:

- A request that carries an `Origin` must come from the API's own address, or from one listed in `api.cors_origins`.
- Without credentials configured, the `Host` header must also be an IP address or `localhost`, which stops DNS rebinding. So without sign-in set up, reach the API by IP address or `localhost`, not by a hostname.
