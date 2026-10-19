#!/usr/bin/env python3
"""Upload feed objects to Cloudflare R2 with SigV4. Stdlib only."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import sys
import urllib.request
from pathlib import Path

BUCKET = "prod-author-cdn"
PREFIX = "metadata/nvm-windows/malicious_packages"


def env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    date_key = sign(("AWS4" + secret).encode("utf-8"), datestamp)
    region_key = sign(date_key, region)
    service_key = sign(region_key, service)
    return sign(service_key, "aws4_request")


def put_object(endpoint: str, access_key: str, secret_key: str, key: str, body: bytes, cache_control: str) -> None:
    host = endpoint.split("://", 1)[1]
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_uri = "/" + "/".join(
        urllib.request.quote(part, safe="") for part in (BUCKET, *key.split("/"))
    )
    canonical_headers = (
        f"cache-control:{cache_control}\n"
        f"content-type:application/octet-stream\n"
        f"host:{host}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "cache-control;content-type;host;x-amz-content-sha256;x-amz-date"
    canonical_request = "\n".join([
        "PUT",
        canonical_uri,
        "",
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    credential_scope = f"{datestamp}/auto/s3/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    signature = hmac.new(
        signing_key(secret_key, datestamp, "auto", "s3"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    authorization = (
        "AWS4-HMAC-SHA256 "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )
    request = urllib.request.Request(
        endpoint + canonical_uri,
        data=body,
        method="PUT",
        headers={
            "Host": host,
            "Content-Type": "application/octet-stream",
            "Cache-Control": cache_control,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
            "Authorization": authorization,
        },
    )
    with urllib.request.urlopen(request) as response:
        if response.status not in (200, 201):
            raise SystemExit(f"R2 PUT {key} returned {response.status}")


def main() -> int:
    account = env("CLOUDFLARE_R2_ACCOUNT_ID")
    access_key = env("CLOUDFLARE_R2_CDN_ACCESS_KEY_ID")
    secret_key = env("CLOUDFLARE_R2_CDN_SECRET_ACCESS_KEY")
    endpoint = env("CLOUDFLARE_R2_ENDPOINT") or f"https://{account}.r2.cloudflarestorage.com"
    missing = [
        name
        for name, value in (
            ("CLOUDFLARE_R2_ACCOUNT_ID", account),
            ("CLOUDFLARE_R2_CDN_ACCESS_KEY_ID", access_key),
            ("CLOUDFLARE_R2_CDN_SECRET_ACCESS_KEY", secret_key),
        )
        if not value
    ]
    if missing:
        raise SystemExit("missing R2 env: " + ", ".join(missing))
    endpoint = endpoint.rstrip("/")
    root = Path(sys.argv[1])
    # Snapshots and deltas are immutable. They are deleted after 30 days.
    immutable = "public, max-age=2592000, immutable"
    uploads: list[tuple[str, Path, str]] = []
    for path in sorted((root / "v1" / "snapshot").glob("*.cbor.gz")):
        uploads.append((f"{PREFIX}/v1/snapshot/{path.name}", path, immutable))
    for path in sorted((root / "v1" / "delta").glob("*.cbor.gz")):
        uploads.append((f"{PREFIX}/v1/delta/{path.name}", path, immutable))
    head = root / "v1" / "head.cose"
    if not head.is_file():
        raise SystemExit("v1/head.cose is missing; sign before upload")
    for key, path, cache_control in uploads:
        put_object(endpoint, access_key, secret_key, key, path.read_bytes(), cache_control)
        print(f"uploaded {key}")
    put_object(endpoint, access_key, secret_key, f"{PREFIX}/v1/head.cose", head.read_bytes(), "public, max-age=3600")
    print(f"uploaded {PREFIX}/v1/head.cose")
    return 0


if __name__ == "__main__":
    sys.exit(main())
