#!/usr/bin/env python3
"""Disabled OSV.dev bulk-export fallback for the malware feed.

The live publisher reads github.com/ossf/malicious-packages. This module is the
planned fallback described in the ops plan. It stays disabled until a weekly
rebuild comparison needs it.
"""

from __future__ import annotations

import argparse
import sys

OSV_CSV = "https://osv-vulnerabilities.storage.googleapis.com/npm/modified_id.csv"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="osv")
    parser.add_argument("--enable", action="store_true", help="reserved; the fallback stays off")
    args = parser.parse_args()
    if args.source != "osv":
        print(f"unknown source {args.source}", file=sys.stderr)
        return 2
    if not args.enable:
        print(
            "OSV.dev fallback is disabled. "
            f"When enabled it would read {OSV_CSV}, keep MAL- IDs only, and stop at the last-seen timestamp.",
            file=sys.stderr,
        )
        return 0
    print("OSV.dev fallback is not implemented yet", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
