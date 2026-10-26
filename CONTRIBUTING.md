# Contributing

Thanks for wanting to help. Bug reports, blocklist-format edge cases and pull requests are all welcome.

## Before you start

For anything bigger than a small fix, open an issue first so we can agree on the approach before you spend time on it. Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Development

You need Rust 1.89 or newer.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --test live -- --ignored   # queries real public resolvers; needs internet
```

To run the server locally without root, point it at a high port:

```sh
cargo run -- --config config/dns.toml   # after changing server.listen to 127.0.0.1:5353
dig @127.0.0.1 -p 5353 example.com
```

`DNS_LOG=dns=debug` logs each blocked name, cache hit and upstream failure.

### Dashboard

The dashboard in `web/` is a React and TypeScript app built with Vite. You need Node 26 and pnpm. Corepack (`npm install -g corepack && corepack enable`) provides the pnpm version pinned in `web/package.json`.

```sh
cd web
pnpm install
pnpm typecheck
pnpm test
pnpm dev   # http://localhost:5173
```

`web/pnpm-workspace.yaml` sets the supply-chain policy: only versions published at least 7 days ago, no trust downgrades, no git or tarball subdependencies, and no install scripts unless a package is listed in `allowBuilds`. Don't loosen these to get an install through. If a release you need is too new, wait for it or pin the previous one.

In development it calls the API at `http://127.0.0.1:8053` (set in `web/public/config.json`), so add `"http://localhost:5173"` to `api.cors_origins` in your local config. Write server data only as React text, never with `dangerouslySetInnerHTML`: domain names come from whoever can query the resolver.

## Pull requests

- Keep each PR to one change, and explain why it is needed, not only what it does.
- Add tests for behavior changes. `tests/e2e.rs` and `tests/encrypted.rs` show how to run the server against fake upstreams.
- CI must pass: formatting, clippy, tests, the MSRV check, the live upstream check and the Docker build.
- Pin third-party GitHub Actions to a full commit SHA with the version in a comment (`uses: owner/action@<sha> # v4`), and Docker base images by digest. GitHub's own `actions/*` may use version tags. Dependabot updates the pins.
- Privacy is a feature here. Changes that log, store or send more about clients' queries need a config switch, off by default unless there's a strong reason.

## License

Unless you say otherwise, any contribution you submit is dual-licensed under MIT OR Apache-2.0, as the project is, without any additional terms or conditions.
