# Security policy

This server sits on the path of every DNS lookup on a network, so security bugs matter here. Thanks for reporting them responsibly.

## Supported versions

The project is pre-1.0. Fixes land on `main` and in the next published image; older images are not patched.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through [GitHub's security advisories](https://github.com/mustafa-zidan/hushdns/security/advisories/new) instead.

Useful details:

- what an attacker can do (spoof answers, bypass blocking, crash the server, read the API without a token, ...)
- the version or commit, and the relevant part of your config
- steps or a packet capture that reproduce it

You can expect an acknowledgement within a week. Once a fix is released, the advisory is published with credit to you unless you'd rather stay anonymous.
