#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.archive import archive_one
from irobot_firmware.catalog import load_catalog, merge_records, write_catalog

CATALOG = Path("data/catalog.json")


def record_id(record: dict) -> str:
    raw = "\0".join(str(record.get(k) or "") for k in ("family", "version", "url"))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def prepare(args: argparse.Namespace) -> int:
    catalog = load_catalog(CATALOG)
    items = []
    for index, record in enumerate(catalog.get("firmwares", [])):
        if record.get("archive"):
            continue
        if args.family and record.get("family") != args.family:
            continue
        items.append({
            "index": index,
            "id": record_id(record),
            "family": record.get("family"),
            "version": record.get("version"),
        })
    payload = json.dumps(items, separators=(",", ":"))
    print(payload)
    if args.github_output:
        with args.github_output.open("a") as f:
            f.write(f"matrix={payload}\n")
            f.write(f"count={len(items)}\n")
            f.write(f"head_sha={os.popen('git rev-parse HEAD').read().strip()}\n")
    return 0


def archive(args: argparse.Namespace) -> int:
    catalog = load_catalog(CATALOG)
    records = catalog.get("firmwares", [])
    if args.index < 0 or args.index >= len(records):
        raise SystemExit(f"catalog index out of range: {args.index}")
    record = records[args.index]
    rid = record_id(record)
    if args.expected_id and rid != args.expected_id:
        raise SystemExit(f"catalog record changed: expected {args.expected_id}, got {rid}")
    if record.get("archive"):
        print(f"already archived: {record.get('family')} {record.get('version')}")
        return 0

    existing_by_sha = {
        str(item["archive"]["sha256"]): item["archive"]
        for item in records
        if item.get("archive", {}).get("sha256")
    }
    archive_data = archive_one(
        record,
        args.repo,
        Path("data"),
        Path("work"),
        upload_release=True,
        deep=True,
        existing_by_sha=existing_by_sha,
    )

    out = args.result_dir
    out.mkdir(parents=True, exist_ok=True)
    result = {
        "id": rid,
        "record": {k: v for k, v in record.items() if k != "archive"},
        "archive": archive_data,
    }
    (out / f"result-{rid}.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    manifest_rel = archive_data.get("manifest")
    if manifest_rel:
        src = Path("data") / manifest_rel
        dst = out / "data" / manifest_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    print(json.dumps(result, indent=2))
    return 0


def merge(args: argparse.Namespace) -> int:
    catalog = load_catalog(CATALOG)
    results = sorted(args.results_dir.rglob("result-*.json"))
    print(f"merging {len(results)} archive results")
    by_key = {
        (r.get("family"), r.get("version"), r.get("url")): r
        for r in catalog.get("firmwares", [])
    }
    for path in results:
        result = json.loads(path.read_text())
        record = result["record"]
        key = (record.get("family"), record.get("version"), record.get("url"))
        target = by_key.get(key)
        if target is None:
            catalog, _ = merge_records(catalog, [record])
            by_key = {
                (r.get("family"), r.get("version"), r.get("url")): r
                for r in catalog.get("firmwares", [])
            }
            target = by_key[key]
        target["archive"] = result["archive"]

    source_manifests = args.results_dir / "data" / "firmware"
    if source_manifests.exists():
        shutil.copytree(source_manifests, Path("data/firmware"), dirs_exist_ok=True)
    write_catalog(CATALOG, catalog)
    print("catalog archived", sum(bool(x.get("archive")) for x in catalog["firmwares"]), "of", len(catalog["firmwares"]))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("prepare")
    p.add_argument("--family")
    p.add_argument("--github-output", type=Path)
    p.set_defaults(func=prepare)

    p = sub.add_parser("archive")
    p.add_argument("--index", type=int, required=True)
    p.add_argument("--expected-id")
    p.add_argument("--repo", required=True)
    p.add_argument("--result-dir", type=Path, default=Path("_bulk_result"))
    p.set_defaults(func=archive)

    p = sub.add_parser("merge")
    p.add_argument("--results-dir", type=Path, default=Path("_bulk_results"))
    p.set_defaults(func=merge)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
