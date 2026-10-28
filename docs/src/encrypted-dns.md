# Encrypted DNS

hushdns encrypts DNS in both directions: from hushdns to the upstream resolvers, and, if you turn it on, from your devices to hushdns.

## Upstreams

`upstream.servers` lists the resolvers queries are forwarded to. They're tried in order until one answers.

```toml
[upstream]
servers = ["tls://1.1.1.1#cloudflare-dns.com", "tls://9.9.9.9#dns.quad9.net"]
bootstrap = ["1.1.1.1", "9.9.9.9"]
timeout_ms = 3000
```

| Transport | Written as |
|---|---|
| DNS-over-TLS | `tls://1.1.1.1#cloudflare-dns.com` (an IP, then the name on its certificate) or `tls://dns.quad9.net` |
| DNS-over-HTTPS | `https://cloudflare-dns.com/dns-query` |
| Plain DNS | `1.1.1.1`, `udp://1.1.1.1:53` or `tcp://1.1.1.1` |

DNS-over-TLS to Cloudflare and Quad9 is the default, so your ISP, or anyone else on the path, can't see or change your lookups. Certificates are checked against the system's trust store.

When an upstream is given by hostname, hushdns looks the hostname up through the plain `bootstrap` servers, never through the operating system's resolver. That way it can safely be its own host's resolver.

Connections to DNS-over-TLS upstreams are kept open and reused. When an upstream hangs up before it answers, the query is retried once on a fresh connection.

## Serving your devices

Set a certificate and key, then turn on the listeners you want:

```toml
[tls]
cert_file = "/etc/hushdns/tls/fullchain.pem"
key_file = "/etc/hushdns/tls/privkey.pem"
dot_listen = ["0.0.0.0:853"]   # DNS-over-TLS, for Android Private DNS and similar
doh_listen = ["0.0.0.0:443"]   # DNS-over-HTTPS at https://<name>/dns-query
doh_path = "/dns-query"
reload_interval_secs = 3600
```

DNS-over-HTTPS works over HTTP/2 and HTTP/1.1, with both GET and POST. Answers carry a `Cache-Control: max-age` equal to their smallest TTL.

The certificate must cover the name your devices connect to, so use one from a public CA such as Let's Encrypt, or from a CA your devices trust. hushdns checks the files every `reload_interval_secs` and picks up a renewed certificate without a restart. If the new files don't load, it keeps serving with the old certificate and logs the error.

### In Docker

Mount the certificate directory and publish the ports:

```sh
docker run -d --name hushdns \
  -p 53:53/udp -p 53:53/tcp -p 853:853/tcp -p 443:443/tcp \
  -v "$PWD/hushdns.toml:/etc/hushdns/hushdns.toml:ro" \
  -v "/etc/letsencrypt/live/dns.example.com:/etc/hushdns/tls:ro" \
  ghcr.io/mustafa-zidan/hushdns:latest
```

The container's user must be able to read the key file. Let's Encrypt's `live` directory holds symlinks into `archive`. If the links don't resolve inside the container, mount the parent `/etc/letsencrypt` instead.

On Kubernetes, the chart can get the certificate from cert-manager. See [Kubernetes](kubernetes.md#dns-over-tls-and-dns-over-https).

## Padding

Encrypted traffic still shows its size, and the size of a DNS message gives away a lot about the name in it. hushdns pads its encrypted queries to 128-byte blocks, and pads its answers to padded queries to 468-byte blocks, as RFC 8467 recommends.
