#!/usr/bin/env python3
"""One-off: rewrite Cache-Control on feed objects and expire archives after 30 days."""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

BUCKET = "prod-author-cdn"
PREFIX = "metadata/nvm-windows/malicious_packages/"
HEAD_CACHE = "public, max-age=3600"
ARCHIVE_CACHE = "public, max-age=2592000, immutable"
NS = "http://s3.amazonaws.com/doc/2006-03-01/"
SNAPSHOT_RULE = "Purge malware feed snapshots"
DELTA_RULE = "Purge malware feed deltas"


def env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret: str, datestamp: str) -> bytes:
    date_key = sign(("AWS4" + secret).encode("utf-8"), datestamp)
    region_key = sign(date_key, "auto")
    service_key = sign(region_key, "s3")
    return sign(service_key, "aws4_request")


def quote_key(key: str) -> str:
    return "/" + "/".join(urllib.request.quote(part, safe="") for part in (BUCKET, *key.split("/")))


def call(
    endpoint: str,
    access_key: str,
    secret_key: str,
    method: str,
    canonical_uri: str,
    query: str,
    extra_headers: dict[str, str],
    body: bytes,
) -> tuple[int, bytes]:
    host = endpoint.split("://", 1)[1]
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    headers = {
        "host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    headers.update({name.lower(): value for name, value in extra_headers.items()})
    if body and "content-type" not in headers:
        headers["content-type"] = "application/xml"
    canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
    signed_headers = ";".join(sorted(headers))
    canonical_request = "\n".join([
        method,
        canonical_uri,
        query,
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
    signature = hmac.new(signing_key(secret_key, datestamp), string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = (
        "AWS4-HMAC-SHA256 "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )
    request_headers = {name: value for name, value in headers.items() if name != "host"}
    request_headers["Host"] = host
    request_headers["Authorization"] = authorization
    url = endpoint + canonical_uri + (("?" + query) if query else "")
    request = urllib.request.Request(url, data=body if method != "GET" else None, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise SystemExit(f"R2 {method} {canonical_uri} returned {error.code}: {detail}") from error


def list_keys(endpoint: str, access_key: str, secret_key: str) -> list[str]:
    keys: list[str] = []
    token = ""
    while True:
        query = f"list-type=2&prefix={urllib.request.quote(PREFIX, safe='')}"
        if token:
            query += "&continuation-token=" + urllib.request.quote(token, safe="")
        query = "&".join(sorted(query.split("&")))
        status, body = call(endpoint, access_key, secret_key, "GET", f"/{BUCKET}", query, {}, b"")
        if status != 200:
            raise SystemExit(f"list returned {status}")
        root = ET.fromstring(body)
        keys.extend(text for node in root.iter() if local(node.tag) == "Key" and (text := (node.text or "")))
        truncated = next((node.text for node in root.iter() if local(node.tag) == "IsTruncated"), "false")
        if truncated != "true":
            return keys
        token = next((node.text or "" for node in root.iter() if local(node.tag) == "NextContinuationToken"), "")
        if not token:
            return keys


def cache_control(key: str) -> str | None:
    if key == PREFIX + "v1/head.cose":
        return HEAD_CACHE
    if key.startswith(PREFIX + "v1/snapshot/") or key.startswith(PREFIX + "v1/delta/"):
        return ARCHIVE_CACHE
    return None


def rewrite(endpoint: str, access_key: str, secret_key: str, key: str, cache_control: str) -> None:
    status, body = call(endpoint, access_key, secret_key, "GET", quote_key(key), "", {}, b"")
    if status != 200:
        raise SystemExit(f"GET {key} returned {status}")
    put_headers = {
        "cache-control": cache_control,
        "content-type": "application/octet-stream",
    }
    status, _ = call(endpoint, access_key, secret_key, "PUT", quote_key(key), "", put_headers, body)
    if status not in (200, 201):
        raise SystemExit(f"PUT {key} returned {status}")
    print(f"rewrote {key} ({len(body)} bytes, {cache_control})")


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def q(name: str) -> str:
    return f"{{{NS}}}{name}"


def child_text(node: ET.Element, name: str) -> str:
    for child in list(node):
        if local(child.tag) == name:
            return child.text or ""
    return ""


def ensure_lifecycle(endpoint: str, access_key: str, secret_key: str) -> None:
    try:
        status, body = call(endpoint, access_key, secret_key, "GET", f"/{BUCKET}", "lifecycle=", {}, b"")
    except SystemExit as error:
        if "returned 404" not in str(error):
            raise
        status, body = 404, b""
    if status == 200 and body.strip():
        root = ET.fromstring(body)
    else:
        root = ET.Element(q("LifecycleConfiguration"))
    ids = {child_text(rule, "ID") for rule in list(root) if local(rule.tag) == "Rule"}
    additions = (
        (SNAPSHOT_RULE, PREFIX + "v1/snapshot/"),
        (DELTA_RULE, PREFIX + "v1/delta/"),
    )
    for rule_id, prefix in additions:
        if rule_id in ids:
            print(f"lifecycle already has {rule_id}")
            continue
        rule = ET.SubElement(root, q("Rule"))
        ET.SubElement(rule, q("ID")).text = rule_id
        filt = ET.SubElement(rule, q("Filter"))
        ET.SubElement(filt, q("Prefix")).text = prefix
        ET.SubElement(rule, q("Status")).text = "Enabled"
        expiration = ET.SubElement(rule, q("Expiration"))
        ET.SubElement(expiration, q("Days")).text = "30"
        print(f"lifecycle add {rule_id} prefix {prefix}")
    payload = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    digest = base64.b64encode(hashlib.md5(payload).digest()).decode("ascii")
    status, _ = call(
        endpoint,
        access_key,
        secret_key,
        "PUT",
        f"/{BUCKET}",
        "lifecycle=",
        {"content-md5": digest, "content-type": "application/xml"},
        payload,
    )
    if status not in (200, 204):
        raise SystemExit(f"lifecycle put returned {status}")
    print("lifecycle saved")


def main() -> int:
    account = env("CLOUDFLARE_R2_ACCOUNT_ID")
    access_key = env("CLOUDFLARE_R2_CDN_ACCESS_KEY_ID")
    secret_key = env("CLOUDFLARE_R2_CDN_SECRET_ACCESS_KEY")
    endpoint = (env("CLOUDFLARE_R2_ENDPOINT") or f"https://{account}.r2.cloudflarestorage.com").rstrip("/")
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
    for key in list_keys(endpoint, access_key, secret_key):
        cache = cache_control(key)
        if cache is None:
            print(f"skip {key}")
            continue
        rewrite(endpoint, access_key, secret_key, key, cache)
    ensure_lifecycle(endpoint, access_key, secret_key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
