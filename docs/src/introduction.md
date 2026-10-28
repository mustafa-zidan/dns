# hushdns

hushdns is a DNS server for your home or office network that blocks ads and trackers and keeps your lookups private. It's written in Rust and inspired by [Technitium DNS Server](https://technitium.com/dns/).

It sits between your devices and an upstream resolver. A query for a domain on one of your blocklists is answered on the spot and never leaves your network. Every other query goes to the upstream over an encrypted connection, and the answer is cached.

![The hushdns dashboard](images/overview.png)

## What it does

- **Blocks ads and trackers** using the blocklists you already know: hosts files, plain domain lists and adblock-style `||domain^` rules. Lists refresh on a schedule, and a rule blocks the domain and all of its subdomains.
- **Encrypts what leaves your network.** By default, upstream queries go over DNS-over-TLS to Cloudflare and Quad9. DNS-over-HTTPS and plain DNS are there too.
- **Serves encrypted DNS to your devices.** DNS-over-TLS works for Android's Private DNS, and DNS-over-HTTPS works for browsers and Apple devices, alongside plain UDP and TCP on port 53.
- **Gives each device its own rules.** Put the kids' tablets in a group with extra lists and a bedtime, and let the work laptop skip the shared blocklists.
- **Comes with a dashboard** for stats, top domains, the state of each list and each client group, and a switch to pause blocking.
- **Runs anywhere:** a small multi-arch container image (`amd64`, `arm64`), a single binary, or a Helm chart.

## Where to start

1. [Install](install.md) it with Docker, compose, a binary or Helm.
2. [Point your devices at it](devices.md).
3. Add [blocklists](blocklists.md) and, if you want, [rules for some devices](clients.md).

The full list of settings is on the [configuration](configuration.md) page.
