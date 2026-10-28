# Logs

Logs go to standard output. `HUSHDNS_LOG` picks what is logged, using the [`tracing` filter syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html), and defaults to `info`.

## JSON

`HUSHDNS_LOG_FORMAT=json` (or `--log-format json`) writes one JSON object per line, ready for Loki, Elasticsearch, `jq` or `kubectl logs | jq`. The default is plain text.

```json
{"timestamp":"2026-10-28T09:09:46.098163Z","level":"INFO","message":"blocklists ready","blocked":1,"allowed":0,"target":"hushdns::blocklist"}
```

## The query log

Nothing is logged per query unless you ask for it. `HUSHDNS_LOG=info,hushdns::query=debug` adds one `query` event for every query, always with the same fields:

| Field | Example |
|---|---|
| `name` | `tracker.ads.example.com` |
| `qtype` | `AAAA` |
| `outcome` | `blocked`, `cached`, `forwarded`, `failed` or `invalid` |
| `rcode` | `NoError`, `NXDomain`, `ServFail` |
| `rule` | the rule that blocked it, or `*` for a schedule that blocks everything |
| `client_ip` | `192.168.1.20` |
| `client_group` | the `[[clients]]` group whose rules blocked it |
| `transport` | `udp`, `tcp`, `dot` or `doh` |
| `duration_ms` | `0.13` |

```json
{"timestamp":"2026-10-28T09:09:47.605160Z","level":"DEBUG","message":"query","name":"ads.example.com","qtype":"A","outcome":"blocked","rcode":"NXDomain","rule":"ads.example.com","client_ip":"127.0.0.1","transport":"udp","duration_ms":0.132468,"target":"hushdns::query"}
```

For example, to count the most blocked names:

```sh
docker logs hushdns | jq -r 'select(.outcome == "blocked") | .name' | sort | uniq -c | sort -rn | head
```

Per-query logs record who looked up what, so turn them on only when you need them.

## Other events

Other events use the same field names where they apply: `client_ip` and `transport` for connections, `upstream` for upstream servers, `list` for blocklists, `listen` for listeners, and `error` for errors.

Shipping logs straight to CloudWatch, Elasticsearch or an OpenTelemetry collector is tracked in [#19](https://github.com/mustafa-zidan/hushdns/issues/19).
