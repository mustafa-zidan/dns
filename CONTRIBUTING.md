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

## Pull requests

- Keep each PR to one change, and explain why it is needed, not only what it does.
- Add tests for behavior changes. `tests/e2e.rs` and `tests/encrypted.rs` show how to run the server against fake upstreams.
- CI must pass: formatting, clippy, tests, the MSRV check, the live upstream check and the Docker build.
- Privacy is a feature here. Changes that log, store or send more about clients' queries need a config switch, off by default unless there's a strong reason.

## License

Unless you say otherwise, any contribution you submit is dual-licensed under MIT OR Apache-2.0, as the project is, without any additional terms or conditions.
