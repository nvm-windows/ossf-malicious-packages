#!/usr/bin/env python3
"""Build a deterministic CBOR malicious-npm feed from an OpenSSF checkout.

Stdlib only. Maps use unsigned integer keys. Output is RFC 8949 section 4.2.1
deterministic CBOR, then gzip with mtime 0.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


FORMAT = 1
KIND_ALL = 0
KIND_VERSIONS = 1
KIND_RANGES = 2
KIND_BOTH = 3

# Snapshot / delta / head integer keys.
KEY_FORMAT = 1
KEY_SEQ = 2
KEY_PUBLISHED = 3
KEY_EXPIRES = 4
KEY_STATE_HASH = 5
KEY_SNAPSHOT = 6
KEY_DELTAS = 7
KEY_POLL_INTERVAL = 8
KEY_MIN_CLIENT = 9
KEY_BASE_HASH = 3
KEY_UPSERTS = 4
KEY_REMOVALS = 5
KEY_ENTRIES = 3

POLL_INTERVAL_SECONDS = 3600
HEAD_TTL_SECONDS = 72 * 60 * 60
MIN_ENTRIES = 100_000
MAX_ENTRIES = 1_000_000
MAX_UPSERTS = 5000
MAX_REMOVALS = 200
UNKNOWN_RANGE_LIMIT = 0.005


def encode_uint(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("unsigned only")
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value < 256:
        return bytes([prefix | 24, value])
    if value < 65536:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value < 4294967296:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    return bytes([prefix | 27]) + value.to_bytes(8, "big")


def cbor(value) -> bytes:
    if isinstance(value, bool):
        raise TypeError("bool is not used")
    if isinstance(value, int):
        if value < 0:
            raise TypeError("negative integers are not used")
        return encode_uint(0, value)
    if isinstance(value, bytes):
        return encode_uint(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return encode_uint(3, len(raw)) + raw
    if value is None:
        return bytes([0xF6])
    if isinstance(value, list):
        return encode_uint(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda pair: cbor(pair[0]))
        body = b"".join(cbor(key) + cbor(item) for key, item in items)
        return encode_uint(5, len(items)) + body
    raise TypeError(type(value).__name__)


def gzip_bytes(payload: bytes) -> bytes:
    return gzip.compress(payload, mtime=0)


def spec_all() -> list:
    return [KIND_ALL]


def spec_versions(versions: list[str]) -> list:
    return [KIND_VERSIONS, sorted(set(versions))]


def spec_ranges(ranges: list[list]) -> list:
    unique = []
    seen = set()
    for introduced, fixed, last_affected in ranges:
        key = (introduced, fixed, last_affected)
        if key not in seen:
            seen.add(key)
            unique.append([introduced, fixed, last_affected])
    unique.sort(key=lambda item: (item[0], item[1] or "", item[2] or ""))
    return [KIND_RANGES, unique]


def spec_both(versions: list[str], ranges: list[list]) -> list:
    return [KIND_BOTH, spec_versions(versions)[1], spec_ranges(ranges)[1]]


def merge_specs(parts: list[list]) -> list:
    if any(part[0] == KIND_ALL for part in parts):
        return spec_all()
    versions: list[str] = []
    ranges: list[list] = []
    for part in parts:
        kind = part[0]
        if kind == KIND_VERSIONS:
            versions.extend(part[1])
        elif kind == KIND_RANGES:
            ranges.extend(part[1])
        elif kind == KIND_BOTH:
            versions.extend(part[1])
            ranges.extend(part[2])
    if versions and ranges:
        return spec_both(versions, ranges)
    if versions:
        return spec_versions(versions)
    if ranges:
        return spec_ranges(ranges)
    return spec_all()


def events_to_range(events: list) -> tuple[str, str | None, str | None, bool]:
    introduced = None
    fixed = None
    last_affected = None
    for event in events:
        if not isinstance(event, dict):
            return ("", None, None, True)
        if "introduced" in event:
            introduced = str(event["introduced"])
        elif "fixed" in event:
            fixed = str(event["fixed"])
        elif "last_affected" in event:
            last_affected = str(event["last_affected"])
        else:
            return ("", None, None, True)
    if introduced is None:
        return ("", None, None, True)
    unbounded = introduced == "0" and fixed is None and last_affected is None
    return (introduced, fixed, last_affected, unbounded)


def affected_to_specs(affected: list) -> tuple[list[tuple[str, list]], int, int]:
    grouped: dict[str, list] = {}
    unknown = 0
    considered = 0
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        if package.get("ecosystem") != "npm":
            continue
        name = package.get("name")
        if not isinstance(name, str) or name == "":
            continue
        considered += 1
        versions = [str(item) for item in entry.get("versions") or [] if isinstance(item, str)]
        ranges = []
        entry_unknown = False
        entry_all = False
        for item in entry.get("ranges") or []:
            if not isinstance(item, dict):
                entry_unknown = True
                continue
            if item.get("type") not in (None, "SEMVER"):
                entry_unknown = True
                continue
            introduced, fixed, last_affected, unbounded = events_to_range(item.get("events") or [])
            if unbounded:
                entry_all = True
                continue
            if introduced == "" or introduced is None:
                entry_unknown = True
                continue
            ranges.append([introduced, fixed, last_affected])
        if entry_unknown:
            unknown += 1
            grouped.setdefault(name, []).append(spec_all())
            continue
        if entry_all and not versions and not ranges:
            grouped.setdefault(name, []).append(spec_all())
            continue
        if entry_all:
            grouped.setdefault(name, []).append(spec_all())
            continue
        if versions and ranges:
            grouped.setdefault(name, []).append(spec_both(versions, ranges))
        elif versions:
            grouped.setdefault(name, []).append(spec_versions(versions))
        elif ranges:
            grouped.setdefault(name, []).append(spec_ranges(ranges))
        else:
            unknown += 1
            grouped.setdefault(name, []).append(spec_all())
    specs = [(name, merge_specs(parts)) for name, parts in grouped.items()]
    return specs, unknown, considered


def load_record(path: Path) -> dict | None:
    if path.name.startswith("MAL-0000-"):
        return None
    record = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(record, dict):
        raise ValueError(f"{path} is not an object")
    if record.get("withdrawn"):
        return None
    if "id" not in record or "modified" not in record:
        raise ValueError(f"{path} is missing id or modified")
    return record


def collect(root: Path) -> tuple[dict[str, list], dict]:
    malicious = root / "osv" / "malicious" / "npm"
    withdrawn = root / "osv" / "withdrawn" / "npm"
    if not malicious.is_dir() or not withdrawn.is_dir():
        raise SystemExit("upstream is missing osv/malicious/npm or osv/withdrawn/npm")
    by_name: dict[str, list] = {}
    mal_ids: dict[str, set[str]] = {}
    unknown = 0
    considered = 0
    majors = set()
    files = 0
    for base in (malicious, withdrawn):
        for path in base.rglob("*.json"):
            if not path.is_file():
                continue
            record = load_record(path)
            if record is None:
                continue
            files += 1
            schema = str(record.get("schema_version") or "")
            if schema:
                majors.add(schema.split(".", 1)[0])
            affected = record.get("affected")
            if not isinstance(affected, list):
                raise SystemExit(f"{path} has no affected array")
            specs, file_unknown, file_considered = affected_to_specs(affected)
            if file_considered == 0:
                raise SystemExit(f"{path} has no npm affected entry")
            unknown += file_unknown
            considered += file_considered
            mal_id = str(record["id"])
            for name, spec in specs:
                by_name.setdefault(name, []).append(spec)
                mal_ids.setdefault(name, set()).add(mal_id)
    merged = {name: merge_specs(parts) for name, parts in by_name.items()}
    stats = {
        "files": files,
        "unknown_ranges": unknown,
        "considered": considered,
        "schema_majors": sorted(majors),
        "mal_ids": mal_ids,
    }
    return merged, stats


def state_hash(entries: list) -> bytes:
    return hashlib.sha256(cbor(entries)).digest()


def sorted_entries(specs: dict[str, list]) -> list:
    return [[name, specs[name]] for name in sorted(specs)]


def load_lines(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.split("#", 1)[0].strip()
        if text:
            names.add(text)
    return names


def load_id_list(path: Path, key: str) -> set[str]:
    if not path.is_file():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(item) for item in data.get(key, [])}


def apply_policy(specs: dict[str, list], mal_ids: dict[str, set[str]], policy: Path) -> tuple[dict[str, list], list[dict]]:
    high_impact = load_lines(policy / "high-impact.txt")
    approvals = load_id_list(policy / "approvals.json", "mal_ids")
    suppressions = load_id_list(policy / "suppressions.json", "mal_ids")
    holds = []
    published = {}
    for name, spec in specs.items():
        ids = mal_ids.get(name, set()) - suppressions
        if not ids:
            continue
        if name in high_impact and spec[0] == KIND_ALL and not ids <= approvals:
            holds.append({"name": name, "mal_ids": sorted(ids), "reason": "high-impact"})
            continue
        published[name] = spec
    return published, holds


def load_state(state_path: Path) -> dict:
    if not state_path.is_file():
        return {}
    return json.loads(state_path.read_text(encoding="utf-8"))


def load_previous_specs(path: Path | None) -> dict[str, list]:
    if path is None or not path.is_file():
        return {}
    raw = gzip.decompress(path.read_bytes())
    entries = decode_entries(raw)
    return {name: spec for name, spec in entries}


def decode_entries(payload: bytes) -> list:
    value, offset = decode_at(payload, 0)
    if offset != len(payload):
        raise ValueError("trailing bytes in previous entries")
    if not isinstance(value, list):
        raise ValueError("previous entries are not an array")
    return value


def read_uint(payload: bytes, offset: int, additional: int) -> tuple[int, int]:
    if additional < 24:
        return additional, offset
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    width = widths[additional]
    end = offset + width
    return int.from_bytes(payload[offset:end], "big"), end


def decode_at(payload: bytes, offset: int):
    initial = payload[offset]
    offset += 1
    major = initial >> 5
    additional = initial & 0x1F
    if major == 0:
        return read_uint(payload, offset, additional)
    if major == 2:
        length, offset = read_uint(payload, offset, additional)
        end = offset + length
        return payload[offset:end], end
    if major == 3:
        length, offset = read_uint(payload, offset, additional)
        end = offset + length
        return payload[offset:end].decode("utf-8"), end
    if major == 7 and additional == 22:
        return None, offset
    if major == 4:
        length, offset = read_uint(payload, offset, additional)
        items = []
        for _ in range(length):
            item, offset = decode_at(payload, offset)
            items.append(item)
        return items, offset
    if major == 5:
        length, offset = read_uint(payload, offset, additional)
        mapping = {}
        for _ in range(length):
            key, offset = decode_at(payload, offset)
            item, offset = decode_at(payload, offset)
            mapping[key] = item
        return mapping, offset
    raise ValueError(f"unsupported CBOR major {major}")


def diff_entries(old: dict[str, list], new: dict[str, list]) -> tuple[list, list]:
    upserts = []
    removals = []
    for name in sorted(set(old) | set(new)):
        if name not in new:
            removals.append(name)
        elif name not in old or old[name] != new[name]:
            upserts.append([name, new[name]])
    return upserts, removals


def object_stamp(published: int) -> str:
    """UTC stamp used as the object name. The client formats the published time the same way."""
    return datetime.fromtimestamp(published, timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def write_outputs(args: argparse.Namespace, entries: list, upserts: list, removals: list, seq: int, published: int, snapshot: bool, state: dict) -> dict:
    out = Path(args.out)
    digest = state_hash(entries)
    snapshot_gz = b""
    snapshot_path = None
    if snapshot:
        snapshot_payload = cbor({
            KEY_FORMAT: FORMAT,
            KEY_SEQ: seq,
            KEY_PUBLISHED: published,
            KEY_ENTRIES: entries,
        })
        snapshot_gz = gzip_bytes(snapshot_payload)
        snapshot_dir = out / "v1" / "snapshot"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        snapshot_path = snapshot_dir / f"{object_stamp(published)}.cbor.gz"
        snapshot_path.write_bytes(snapshot_gz)
        snapshot_sha = hashlib.sha256(snapshot_gz).digest()
        snapshot_size = len(snapshot_gz)
        snapshot_seq = seq
        snapshot_published = published
    else:
        snapshot_sha = bytes.fromhex(state["snapshot_sha256"])
        snapshot_size = int(state["snapshot_size"])
        snapshot_seq = int(state["snapshot_seq"])
        snapshot_published = int(state["snapshot_published"])
    base_hash = bytes(32) if int(state.get("seq") or 0) == 0 else bytes.fromhex(state["state_hash"])
    delta_payload = cbor({
        KEY_FORMAT: FORMAT,
        KEY_SEQ: seq,
        KEY_BASE_HASH: base_hash,
        KEY_UPSERTS: upserts,
        KEY_REMOVALS: removals,
    })
    delta_gz = gzip_bytes(delta_payload)
    delta_dir = out / "v1" / "delta"
    delta_dir.mkdir(parents=True, exist_ok=True)
    delta_path = delta_dir / f"{object_stamp(published)}.cbor.gz"
    delta_path.write_bytes(delta_gz)
    delta_sha = hashlib.sha256(delta_gz).digest()
    prior_deltas = [] if snapshot else list(state.get("deltas") or [])
    prior_deltas.append({
        "seq": seq,
        "published": published,
        "sha256": delta_sha.hex(),
        "size": len(delta_gz),
    })
    delta_tuples = [
        [int(item["seq"]), bytes.fromhex(item["sha256"]), int(item["size"]), int(item["published"])]
        for item in prior_deltas
    ]
    head = cbor({
        KEY_FORMAT: FORMAT,
        KEY_SEQ: seq,
        KEY_PUBLISHED: published,
        KEY_EXPIRES: published + HEAD_TTL_SECONDS,
        KEY_STATE_HASH: digest,
        KEY_SNAPSHOT: [snapshot_seq, snapshot_sha, snapshot_size, snapshot_published],
        KEY_DELTAS: [] if snapshot else delta_tuples,
        KEY_POLL_INTERVAL: POLL_INTERVAL_SECONDS,
        KEY_MIN_CLIENT: FORMAT,
    })
    head_path = out / "v1" / "head-payload.cbor"
    head_path.parent.mkdir(parents=True, exist_ok=True)
    head_path.write_bytes(head)
    (out / "entries.cbor.gz").write_bytes(gzip_bytes(cbor(entries)))
    return {
        "seq": seq,
        "state_hash": digest.hex(),
        "snapshot": "" if snapshot_path is None else str(snapshot_path),
        "snapshot_sha256": snapshot_sha.hex(),
        "snapshot_size": snapshot_size,
        "snapshot_published": snapshot_published,
        "delta": str(delta_path),
        "delta_sha256": delta_sha.hex(),
        "delta_size": len(delta_gz),
        "deltas": [] if snapshot else prior_deltas,
        "head_payload": str(head_path),
        "entry_count": len(entries),
        "wrote_snapshot": snapshot,
    }


def self_test() -> None:
    encoded = cbor({2: "b", 1: 1})
    if encoded != bytes([0xA2, 0x01, 0x01, 0x02, 0x61, 0x62]):
        raise SystemExit(f"cbor map order mismatch: {encoded.hex()}")
    sample = {
        "id": "MAL-2024-1",
        "modified": "2024-01-01T00:00:00Z",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "left-pad"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
        }],
    }
    specs, unknown, considered = affected_to_specs(sample["affected"])
    if unknown or considered != 1 or specs != [("left-pad", spec_all())]:
        raise SystemExit("ALL range was not recognized")
    print("self-test ok")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--policy", type=Path, default=Path("policy"))
    parser.add_argument("--state", type=Path, default=Path("state.json"))
    parser.add_argument("--out", type=Path, default=Path("dist"))
    parser.add_argument("--production", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--published", type=int, default=0)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--upstream-sha", default="")
    parser.add_argument("--upstream-commit-time", default="")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.upstream is None:
        parser.error("--upstream is required")
    specs, stats = collect(args.upstream)
    published_specs, holds = apply_policy(specs, stats["mal_ids"], args.policy)
    considered = max(stats["considered"], 1)
    if stats["unknown_ranges"] / considered > UNKNOWN_RANGE_LIMIT:
        raise SystemExit("unknown range types exceed 0.5 percent")
    if args.production and not (MIN_ENTRIES <= len(published_specs) <= MAX_ENTRIES):
        raise SystemExit(f"entry count {len(published_specs)} is outside {MIN_ENTRIES}..{MAX_ENTRIES}")
    entries = sorted_entries(published_specs)
    digest = state_hash(entries)
    state = load_state(args.state)
    previous_raw = state.get("state_hash") or ""
    previous_hash = bytes.fromhex(previous_raw) if len(previous_raw) == 64 else None
    status_path = Path(args.out) / "status.json"
    status_path.parent.mkdir(parents=True, exist_ok=True)
    if previous_hash == digest:
        status_path.write_text(json.dumps({"outcome": "unchanged", "state_hash": digest.hex()}), encoding="utf-8")
        print("unchanged")
        return 0
    previous_seq = int(state.get("seq") or 0)
    old_specs = load_previous_specs(args.previous) if previous_seq else {}
    if previous_seq and (args.previous is None or not args.previous.is_file()):
        raise SystemExit("previous entries file is required after the first publish")
    seq = previous_seq + 1
    since_snapshot = seq - int(state.get("snapshot_seq") or 0)
    # A snapshot without a published time cannot be named, so write one.
    snapshot = previous_seq == 0 or since_snapshot >= 24 or not state.get("snapshot_published")
    upserts, removals = diff_entries(old_specs, published_specs)
    previous_count = int(state.get("entry_count") or 0)
    if previous_count and len(published_specs) < previous_count * 0.99:
        raise SystemExit("entry count dropped by more than 1 percent")
    oversize = len(upserts) > MAX_UPSERTS or len(removals) > MAX_REMOVALS
    approvals = {}
    approvals_path = args.policy / "approvals.json"
    if approvals_path.is_file():
        approvals = json.loads(approvals_path.read_text(encoding="utf-8"))
    # The first snapshot is the whole dataset, so it is over the hourly size guard.
    # Later runs still hold until publish_oversize is set.
    if oversize and previous_seq != 0 and not approvals.get("publish_oversize"):
        holds.append({"reason": "size", "upserts": len(upserts), "removals": len(removals)})
    if any(item.get("reason") == "size" for item in holds):
        status = {"outcome": "held", "holds": holds, "seq": seq, "entry_count": len(entries)}
        status_path.write_text(json.dumps(status, indent=2), encoding="utf-8")
        print(f"held seq={seq} entries={len(entries)}")
        return 0
    published_at = args.published or 0
    if published_at == 0:
        raise SystemExit("--published unix time is required when the feed changes")
    info = write_outputs(args, entries, upserts, removals, seq, published_at, snapshot, state)
    info["outcome"] = "ready"
    info["holds"] = [item for item in holds if item.get("reason") == "high-impact"]
    info["upstream_files"] = stats["files"]
    info["schema_majors"] = stats["schema_majors"]
    status_path.write_text(json.dumps(info, indent=2), encoding="utf-8")
    next_state = {
        "format": FORMAT,
        "seq": seq,
        "upstream_sha": args.upstream_sha,
        "upstream_commit_time": args.upstream_commit_time,
        "state_hash": info["state_hash"],
        "snapshot_seq": seq if info["wrote_snapshot"] else int(state.get("snapshot_seq") or seq),
        "snapshot_published": info["snapshot_published"],
        "snapshot_sha256": info["snapshot_sha256"],
        "snapshot_size": info["snapshot_size"],
        "deltas": info["deltas"],
        "published": published_at,
        "entry_count": len(entries),
    }
    (Path(args.out) / "state.json").write_text(json.dumps(next_state, indent=2) + "\n", encoding="utf-8")
    print(f"ready seq={seq} entries={len(entries)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
