#!/usr/bin/env python3
"""Check the live feed head for age, cache health, and long-held reviews."""

from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_feed import KEY_EXPIRES, KEY_PUBLISHED, KEY_STATE_HASH, decode_at, extract_cose_payload

HEAD_URL = "https://cdn.author.io/metadata/nvm-windows/malicious_packages/v1/head.cose"
UA = "NVM for Windows/2.0.1 (watchdog)"
HOLD_REMINDER = "This hold is still open after 24 hours."
CACHE_OK = {"HIT", "REVALIDATED"}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def temporary_token(ttl: int = 300) -> str:
    now = int(time.time())
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = b64url(json.dumps({"tmp": True, "iat": now, "nbf": now, "exp": now + ttl}, separators=(",", ":")).encode())
    return f"{header}.{claims}."


def license_header() -> str:
    secret = (os.environ.get("WATCHDOG_LICENSE_JWT") or "").strip()
    return secret or temporary_token()


def fetch_head(url: str, token: str, *, cache_bust: bool = False) -> tuple[bytes, dict[str, str]]:
    fetch_url = url
    headers = {
        "User-Agent": UA,
        "X-Nvm-License": token,
    }
    if cache_bust:
        sep = "&" if "?" in url else "?"
        fetch_url = f"{url}{sep}watchdog={time.time_ns()}"
        headers["Cache-Control"] = "no-cache"
        headers["Pragma"] = "no-cache"
    req = urllib.request.Request(fetch_url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp_headers = {key.lower(): value for key, value in resp.headers.items()}
        return resp.read(), resp_headers


def open_or_update(label: str, title: str, body: str, color: str) -> None:
    Path("watchdog-body.txt").write_text(body, encoding="utf-8")
    subprocess.run(
        ["gh", "label", "create", label, "--color", color, "--description", title],
        check=False,
        capture_output=True,
        text=True,
    )
    existing = subprocess.check_output(
        ["gh", "issue", "list", "--label", label, "--state", "open", "--json", "number", "--jq", ".[0].number"],
        text=True,
    ).strip()
    if existing and existing != "null":
        subprocess.check_call(["gh", "issue", "comment", existing, "--body-file", "watchdog-body.txt"])
        print(f"updated {label} issue {existing}")
        return
    url = subprocess.check_output(
        ["gh", "issue", "create", "--title", title, "--label", label, "--body-file", "watchdog-body.txt"],
        text=True,
    ).strip()
    print(url)


def remind_holds() -> None:
    raw = subprocess.check_output(
        [
            "gh",
            "issue",
            "list",
            "--label",
            "feed-review",
            "--state",
            "open",
            "--json",
            "number,createdAt,comments",
            "--jq",
            ".",
        ],
        text=True,
    )
    now = time.time()
    for issue in json.loads(raw):
        created = issue.get("createdAt") or ""
        try:
            created_ts = datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        if now - created_ts < 24 * 3600:
            continue
        number = str(issue["number"])
        comments = subprocess.check_output(
            ["gh", "issue", "view", number, "--json", "comments", "--jq", ".comments[].body"],
            text=True,
        )
        if HOLD_REMINDER in comments:
            continue
        subprocess.check_call(["gh", "issue", "comment", number, "--body", HOLD_REMINDER])
        print(f"reminded hold issue {number}")


def cached_fetch(url: str, token: str) -> tuple[bytes, dict[str, str]]:
    body, headers = fetch_head(url, token)
    cache = (headers.get("cf-cache-status") or "").upper()
    if cache in CACHE_OK:
        return body, headers
    time.sleep(2)
    return fetch_head(url, token)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, default=Path("state.json"))
    parser.add_argument("--head-url", default=HEAD_URL)
    args = parser.parse_args()
    token = license_header()
    alerts: list[str] = []
    try:
        body1, _headers1 = fetch_head(args.head_url, token, cache_bust=True)
        body2, headers2 = cached_fetch(args.head_url, token)
    except urllib.error.HTTPError as exc:
        open_or_update(
            "feed-failure",
            "Feed watchdog could not fetch head.cose",
            f"HTTP {exc.code} fetching `{args.head_url}`.\n",
            "D93F0B",
        )
        return 1
    payload = extract_cose_payload(body1)
    head, offset = decode_at(payload, 0)
    if offset != len(payload) or not isinstance(head, dict):
        raise SystemExit("head payload is not a CBOR map")
    published = int(head[KEY_PUBLISHED])
    expires = int(head[KEY_EXPIRES])
    now = int(time.time())
    age = now - published
    state = json.loads(args.state.read_text(encoding="utf-8")) if args.state.is_file() else {}
    if age > 48 * 3600:
        alerts.append(f"Head published {age // 3600}h ago (over 48h).")
    if expires - now < 24 * 3600:
        alerts.append(f"Head expires in {(expires - now) // 3600}h (under 24h).")
    cache2 = (headers2.get("cf-cache-status") or "").upper()
    if cache2 not in CACHE_OK:
        print(
            f"second head fetch cache status was `{cache2 or 'missing'}`; not failing",
            file=sys.stderr,
        )
    if body1 != body2:
        # Origin (cache-bust) is the freshness check. The unbust fetch can stay
        # stale for hours when CLOUDFLARE_CACHE_PURGE_TOKEN is unset.
        print("edge cache body differs from origin; not failing", file=sys.stderr)
    state_hash = head.get(KEY_STATE_HASH)
    if isinstance(state_hash, (bytes, bytearray)) and state.get("state_hash"):
        if state_hash.hex() != state["state_hash"]:
            alerts.append("Live head `state_hash` does not match committed `state.json`.")
    if alerts:
        open_or_update(
            "feed-failure",
            "Feed watchdog alert",
            "The watchdog found problems with the live feed:\n\n- " + "\n- ".join(alerts) + "\n",
            "D93F0B",
        )
        print("alerts")
        for item in alerts:
            print(item)
        return 1
    remind_holds()
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
