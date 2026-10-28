# Install

hushdns reads one TOML config file. Every key is optional, so it runs with no config at all: it listens on port 53, forwards over DNS-over-TLS to Cloudflare and Quad9, and blocks nothing until you add lists. The [configuration](configuration.md) page lists every setting.

## Docker

Images for `linux/amd64` and `linux/arm64` are published to GitHub Container Registry.

```sh
docker run -d --name hushdns --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp \
  ghcr.io/mustafa-zidan/hushdns:latest
```

The image ships with the [example config](configuration.md#the-example-file), which loads two popular blocklists. To use your own config, mount it over `/etc/hushdns/hushdns.toml`:

```sh
docker run -d --name hushdns --restart unless-stopped \
  -p 53:53/udp -p 53:53/tcp \
  -v "$PWD/hushdns.toml:/etc/hushdns/hushdns.toml:ro" \
  ghcr.io/mustafa-zidan/hushdns:latest
```

The container runs as a non-root user on distroless Debian. It runs in UTC, so set `server.timezone` if you use [schedules](clients.md#schedules).

Tags follow releases: `latest` is the newest build from `main`, `0.0.1` is an exact release, and `0.0` is the newest patch release of that line.

## Docker Compose, with the dashboard

The [compose example](https://github.com/mustafa-zidan/hushdns/tree/main/examples/compose) runs the server and the [dashboard](dashboard.md) together:

```sh
git clone https://github.com/mustafa-zidan/hushdns
cd hushdns/examples/compose
# Set api.token in hushdns.toml first.
docker compose up -d
```

Then open <http://localhost:8080> and enter the token.

## Binary

Every [release](https://github.com/mustafa-zidan/hushdns/releases) has binaries for Linux on `x86_64` and `aarch64`, with a `SHA256SUMS` file:

```sh
version=0.0.1
arch=$(uname -m)   # x86_64 or aarch64
curl -LO "https://github.com/mustafa-zidan/hushdns/releases/download/v$version/hushdns-$version-$arch-linux.tar.gz"
curl -LO "https://github.com/mustafa-zidan/hushdns/releases/download/v$version/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
tar xzf "hushdns-$version-$arch-linux.tar.gz"
sudo install "hushdns-$version-$arch-linux/hushdns" /usr/local/bin/
```

Run it with a config file:

```sh
hushdns --config /etc/hushdns/hushdns.toml
```

Binding port 53 needs root or the `CAP_NET_BIND_SERVICE` capability. To give the binary just that capability:

```sh
sudo setcap cap_net_bind_service=+ep /usr/local/bin/hushdns
```

To check a config file without starting the server:

```sh
hushdns --check-config --config /etc/hushdns/hushdns.toml
```

## Kubernetes

A Helm chart runs the server and the dashboard, configured entirely through values:

```sh
helm install hushdns oci://ghcr.io/mustafa-zidan/charts/hushdns \
  --set service.type=LoadBalancer
```

The [Kubernetes](kubernetes.md) page covers serving your LAN, TLS with cert-manager, and the dashboard.

## From source

You need Rust 1.89 or newer.

```sh
git clone https://github.com/mustafa-zidan/hushdns
cd hushdns
cargo run --release -- --config config/hushdns.toml
```

For local testing without root, set `server.listen` to a high port such as `127.0.0.1:5353`, then try it:

```sh
dig @127.0.0.1 -p 5353 example.com
```
