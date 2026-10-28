# Privacy

hushdns is meant to keep what you look up between you and the resolver you chose, and to keep as little as it can itself.

## What leaves your network

- **Blocked names don't leave at all.** They're answered locally.
- **Upstream queries are encrypted** by default, over DNS-over-TLS. See [Encrypted DNS](encrypted-dns.md).
- **Upstream queries carry nothing about the client.** Each one gets a fresh random ID and source port, and none of the client's EDNS options are passed on. So EDNS Client Subnet never reveals your network.
- **Encrypted queries are padded** to 128-byte blocks (RFC 8467), so their size doesn't give away the name.
- **DoH requests send no User-Agent.**
- **Upstream hostnames are resolved through the bootstrap servers you configure**, never through the operating system's resolver.

## What hushdns keeps

- **No query log by default.** One log line per query appears only if you turn on `hushdns::query=debug`. See [Logs](logs.md).
- **Stats live in memory only**, and are gone when the server restarts. The top domains lists count queries per domain. Set `stats.top_domains = false` to keep no record of which names were looked up, and only totals are kept.
- **The cache holds answers, not who asked for them.**

## The dashboard

The dashboard loads nothing from other sites, keeps its token only in that browser tab, and can only call the API it's configured for. See [Dashboard](dashboard.md#security).
