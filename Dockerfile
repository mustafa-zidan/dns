# Base images are pinned by digest; Dependabot keeps the digests current.
FROM rust:1-trixie@sha256:931c2c0531a8b143e044f0f3914dfe802f15bb3d1955f0b657e9359327ac2ffc AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && cp target/release/hushdns /usr/local/bin/hushdns

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e
LABEL org.opencontainers.image.title="hushdns" \
      org.opencontainers.image.description="An ad-blocking, privacy-focused DNS server" \
      org.opencontainers.image.source="https://github.com/mustafa-zidan/hushdns" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"
COPY --from=builder /usr/local/bin/hushdns /usr/local/bin/hushdns
COPY config/hushdns.toml /etc/hushdns/hushdns.toml
ENV HUSHDNS_CONFIG=/etc/hushdns/hushdns.toml
# Docker lets unprivileged users bind ports below 1024 inside the container,
# so the server can listen on 53 without running as root.
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp
USER nonroot
ENTRYPOINT ["/usr/local/bin/hushdns"]
