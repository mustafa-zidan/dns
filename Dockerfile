# Base images are pinned by digest; Dependabot keeps the digests current.
FROM rust:1-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8 AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/dns /usr/local/bin/dns

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
LABEL org.opencontainers.image.title="dns" \
      org.opencontainers.image.description="An ad-blocking, privacy-focused DNS server" \
      org.opencontainers.image.source="https://github.com/mustafa-zidan/dns" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /usr/local/bin/dns /usr/local/bin/dns
COPY config/dns.toml /etc/dns/dns.toml
ENV DNS_CONFIG=/etc/dns/dns.toml
# Docker lets unprivileged users bind ports below 1024 inside the container,
# so the server can listen on 53 without running as root.
EXPOSE 53/udp 53/tcp
USER nonroot
ENTRYPOINT ["/usr/local/bin/dns"]
