# OpenSSF malicious npm feed

Hourly GitHub Actions job. It reads [ossf/malicious-packages](https://github.com/ossf/malicious-packages) and writes a deterministic CBOR feed to `prod-author-cdn/metadata/nvm-windows/malicious_packages/`.

Only `v1/head.cose` is signed. See [docs/signing.md](docs/signing.md).

The first full publish is larger than 5,000 upserts, so it is held. Review it, then set `publish_oversize` to `true` in `policy/approvals.json`.
