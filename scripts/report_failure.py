#!/usr/bin/env python3
"""Open or update one feed-failure GitHub issue for a failed workflow run."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def run(args: list[str], check: bool = True) -> str:
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, args, result.stdout, result.stderr)
    return (result.stdout or "").strip()


def main() -> int:
    workflow = os.environ.get("GITHUB_WORKFLOW", "feed")
    run_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    body = (
        f"The `{workflow}` run failed.\n\n"
        f"Log: {run_url}/{repo}/actions/runs/{run_id}\n"
        "Rerun once after reading the failing step. A validation failure means upstream data changed.\n"
    )
    Path("failure-body.txt").write_text(body, encoding="utf-8")
    run(
        ["gh", "label", "create", "feed-failure", "--color", "D93F0B", "--description", "Feed workflow failed"],
        check=False,
    )
    existing = run(
        ["gh", "issue", "list", "--label", "feed-failure", "--state", "open", "--json", "number", "--jq", ".[0].number"]
    )
    if existing and existing != "null":
        run(["gh", "issue", "comment", existing, "--body-file", "failure-body.txt"])
        print(f"updated issue {existing}")
        return 0
    url = run(
        ["gh", "issue", "create", "--title", "Feed workflow failed", "--label", "feed-failure", "--body-file", "failure-body.txt"]
    )
    print(url)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(exc.stderr or exc, file=sys.stderr)
        raise SystemExit(1)
