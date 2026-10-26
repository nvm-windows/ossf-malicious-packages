# OpenSSF malicious npm feed

Hourly GitHub Actions job. It reads [ossf/malicious-packages](https://github.com/ossf/malicious-packages) and writes a deterministic CBOR feed to `prod-author-cdn/metadata/nvm-windows/malicious_packages/`.

Only `v1/head.cose` is signed. See [docs/signing.md](docs/signing.md).

## Workflows

- `publish.yml` — hourly at minute 17. Unchanged feed still commits `upstream_sha`. A size hold opens a `feed-review` issue and an approve pull request. Failures open or update a `feed-failure` issue. If the previous-entries cache expired, publish writes a recovery snapshot instead of failing.
- `rebuild.yml` — daily at `43 5 * * *` UTC. Full collect compared to `state.json`. Drift opens a `feed-drift` issue and publishes a corrective delta through the same guards. A missing previous-entries cache publishes a recovery snapshot without opening drift.
- `watchdog.yml` — every six hours at minute 29. Fails on hash mismatch, a head older than 48h, or HTTP errors. Cache MISS, a stale edge copy, and ossf tip lag do not fail. Reminds open holds older than 24 hours.

Optional secret `WATCHDOG_LICENSE_JWT` is used when set. Otherwise the watchdog mints a short-lived temporary token for the malware paths.

The OSV.dev bulk-export fallback in `scripts/osv_source.py` stays disabled.
