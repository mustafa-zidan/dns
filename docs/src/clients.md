# Per-client rules and schedules

Groups in `[[clients]]` match queries by their source address and change what gets blocked for them. Each group can have its own denylist, allowlist and lists, can skip the shared blocklists, and can have schedules.

```toml
[server]
timezone = "Europe/Berlin"

[[clients]]
name = "kids"
addresses = ["192.168.1.20", "192.168.1.64/28"]
denylist = ["youtube.com", "tiktok.com"]
allowlist = ["school.example"]
lists = ["https://example.com/social-media.txt"]

# Bedtime: on school nights, block everything but the allowlist.
[[clients.schedules]]
days = ["sun", "mon", "tue", "wed", "thu"]
from = "21:00"
to = "07:00"
block_all = true

[[clients]]
name = "work-laptop"
addresses = ["192.168.1.30", "fd00::30"]
blocklists = false   # skip the shared lists; this group's own rules still apply
```

## Matching

`addresses` takes IPv4 and IPv6 addresses and networks. When an address is in several groups, the most specific network wins, so `192.168.1.20` beats `192.168.1.0/24`. A query that matches no group gets only the shared `[blocking]` rules.

## The order rules are checked in

For a query from a group's address:

1. The group's `allowlist`. A match is never blocked.
2. Any of the group's schedules that is open right now.
3. The group's `denylist` and its own `lists`.
4. The shared `[blocking]` rules, unless the group sets `blocklists = false`. The shared allowlist still applies.

A group's own `lists` use the same formats as the shared ones, and load and refresh along with them.

## Schedules

A schedule is a time window with extra rules. It opens on the `days` listed (every day if `days` is left out) and runs from `from` to `to`, as `HH:MM`. A window that ends before it starts runs past midnight. So the bedtime above opens Sunday to Thursday at 21:00 and closes at 07:00 the next morning, which covers Thursday night into Friday morning but not Friday night.

While a window is open, it either blocks everything except the group's allowlist (`block_all = true`), or blocks the names in its own `denylist`:

```toml
[[clients.schedules]]
days = ["mon", "tue", "wed", "thu", "fri"]
from = "08:00"
to = "15:00"
denylist = ["games.example"]
```

Times are in `server.timezone`, or the system's zone when it's unset. The Docker image runs in UTC, so set `server.timezone` there.

## Pausing a group

You can pause one group's rules, so its devices get only the shared rules for a while. Do it from the [dashboard](dashboard.md) or the API:

```sh
curl -X PUT localhost:8053/api/clients/kids -H 'content-type: application/json' \
  -d '{"pause_secs": 1800}'    # 30 minutes; {"pause_secs": 0} resumes
```

Turning blocking off, or pausing it, turns off client rules as well.

## Checking what a device gets

Add the device's address to a check, and you get the answer it would get:

```sh
curl 'localhost:8053/api/check?name=youtube.com&client=192.168.1.20'
```

## Client addresses

The server sees the address each query arrives from:

- Behind NAT, or behind a router that forwards DNS for you, every device looks like that box. See [Point your devices at it](devices.md#the-whole-network-through-your-router).
- In Docker, the published UDP and TCP ports usually keep client addresses. If every query appears to come from the Docker gateway, run the container with `--network host`.
- On Kubernetes, the chart sets `externalTrafficPolicy: Local` so the real addresses get through.
