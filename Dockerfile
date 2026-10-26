# Base images are pinned by digest; Dependabot keeps the digests current.
FROM rust:1-trixie@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/dns /usr/local/bin/dns

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e
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
