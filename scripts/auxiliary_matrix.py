#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.analyze import analyze
from irobot_firmware.auxiliary import iter_auxiliary_bundle_entries
from irobot_firmware.catalog import load_catalog
from irobot_firmware.download import download
from irobot_firmware.util import load_json, save_json, sha256_file

CATALOG = Path("data/catalog.json")
DATA_ROOT = Path("data")


def walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def item_id(manifest: str, parent_sha256: str) -> str:
    return hashlib.sha256(f"{manifest}\0{parent_sha256}".encode()).hexdigest()[:16]


def _record_for_manifest(catalog: dict[str, Any], manifest_rel: str) -> tuple[int, dict[str, Any]] | None:
    for index, record in enumerate(catalog.get("firmwares") or []):
        if str((record.get("archive") or {}).get("manifest") or "") == manifest_rel:
            return index, record
    return None


def _missing_bundle_keys(manifest: dict[str, Any]) -> list[tuple[str, str]]:
    missing: list[tuple[str, str]] = []
    for entry in iter_auxiliary_bundle_entries(manifest):
        if not isinstance(entry.get("auxiliary_firmware"), dict):
            missing.append((str(entry["path"]), str(entry["sha256"])))
    return missing


def prepare(args: argparse.Namespace) -> int:
    catalog = load_catalog(CATALOG)
    seen_manifests: set[str] = set()
    items: list[dict[str, Any]] = []
    for record in catalog.get("firmwares") or []:
        archive = record.get("archive") or {}
        manifest_rel = str(archive.get("manifest") or "")
        if not manifest_rel or manifest_rel in seen_manifests:
            continue
        seen_manifests.add(manifest_rel)
        manifest_path = DATA_ROOT / manifest_rel
        if not manifest_path.is_file():
            continue
        manifest = load_json(manifest_path, {})
        missing = _missing_bundle_keys(manifest)
        if not missing:
            continue
        if args.family and record.get("family") != args.family:
            continue
        parent_sha = str(archive.get("sha256") or "")
        asset_url = str(archive.get("asset_url") or "")
        if not parent_sha or not asset_url:
            print(f"skip {manifest_rel}: no archived SHA/asset URL", file=sys.stderr)
            continue
        found = _record_for_manifest(catalog, manifest_rel)
        if found is None:
            continue
        index, canonical = found
        items.append({
            "index": index,
            "id": item_id(manifest_rel, parent_sha),
            "family": canonical.get("family"),
            "version": canonical.get("version"),
            "manifest": manifest_rel,
            "missing_bundles": len(missing),
        })
    payload = json.dumps(items, separators=(",", ":"))
    print(payload)
    if args.github_output:
        with args.github_output.open("a") as fh:
            fh.write(f"matrix={payload}\n")
            fh.write(f"count={len(items)}\n")
            fh.write(f"head_sha={os.popen('git rev-parse HEAD').read().strip()}\n")
    return 0


def enrich(args: argparse.Namespace) -> int:
    catalog = load_catalog(CATALOG)
    records = catalog.get("firmwares") or []
    if args.index < 0 or args.index >= len(records):
        raise SystemExit(f"catalog index out of range: {args.index}")
    record = records[args.index]
    archive = record.get("archive") or {}
    manifest_rel = str(archive.get("manifest") or "")
    parent_sha = str(archive.get("sha256") or "")
    rid = item_id(manifest_rel, parent_sha)
    if args.expected_id and rid != args.expected_id:
        raise SystemExit(f"archive record changed: expected {args.expected_id}, got {rid}")
    source_manifest_path = DATA_ROOT / manifest_rel
    source_manifest = load_json(source_manifest_path, {})
    missing = _missing_bundle_keys(source_manifest)
    if not missing:
        print(f"already enriched: {manifest_rel}")
        return 0

    asset_url = str(archive.get("asset_url") or "")
    if not asset_url:
        raise SystemExit(f"no archived asset URL for {manifest_rel}")
    filename = urllib.parse.unquote(Path(urllib.parse.urlsplit(asset_url).path).name) or "firmware.bin"
    blob = args.work_dir / "input" / filename
    meta = download(asset_url, blob, expected_size=int(archive.get("size") or 0) or None)
    if str(meta["sha256"]) != parent_sha:
        raise SystemExit(f"parent SHA mismatch: expected {parent_sha}, got {meta['sha256']}")

    analyzed_path = args.work_dir / "reanalyzed.json"
    analyzed = analyze(blob, analyzed_path, args.work_dir / "analysis", deep=True)
    if analyzed.get("sha256") != parent_sha:
        raise SystemExit("reanalyzed parent SHA mismatch")
    analyzed_entries = {
        (str(entry["path"]), str(entry["sha256"])): entry
        for entry in iter_auxiliary_bundle_entries(analyzed)
    }
    enrichments: list[dict[str, Any]] = []
    for path, sha in missing:
        entry = analyzed_entries.get((path, sha))
        if entry is None:
            raise SystemExit(f"reanalyzed package did not reproduce aux bundle {path} {sha}")
        nested = entry.get("auxiliary_firmware")
        if not isinstance(nested, dict):
            raise SystemExit(f"aux bundle was not analyzable as tar: {path} {sha}")
        enrichments.append({
            "path": path,
            "sha256": sha,
            "auxiliary_firmware": nested,
        })

    args.result_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "id": rid,
        "manifest": manifest_rel,
        "parent_sha256": parent_sha,
        "archive_asset_url": asset_url,
        "enrichments": enrichments,
    }
    save_json(args.result_dir / f"result-{rid}.json", result)
    print(f"enriched {manifest_rel}: {len(enrichments)} bundle(s)")
    return 0


def merge(args: argparse.Namespace) -> int:
    results = sorted(args.results_dir.rglob("result-*.json"))
    print(f"merging {len(results)} auxiliary analysis results")
    changed_manifests = 0
    enriched_entries = 0
    for result_path in results:
        result = load_json(result_path, {})
        manifest_rel = str(result.get("manifest") or "")
        manifest_path = DATA_ROOT / manifest_rel
        manifest = load_json(manifest_path, {})
        if str(manifest.get("sha256") or "") != str(result.get("parent_sha256") or ""):
            raise SystemExit(f"current manifest parent SHA changed: {manifest_rel}")
        by_key = {
            (str(node.get("path")), str(node.get("sha256"))): node
            for node in walk(manifest)
            if isinstance(node.get("path"), str) and node.get("sha256")
        }
        changed = False
        for enrichment in result.get("enrichments") or []:
            key = (str(enrichment["path"]), str(enrichment["sha256"]))
            target = by_key.get(key)
            if target is None:
                raise SystemExit(f"current manifest no longer contains aux bundle {key}: {manifest_rel}")
            nested = enrichment.get("auxiliary_firmware")
            if target.get("auxiliary_firmware") == nested:
                continue
            target["auxiliary_firmware"] = nested
            target["auxiliary_firmware_provenance"] = {
                "method": "reanalyzed-archived-parent-release",
                "bundle_sha256": key[1],
                "archive_asset_url": result.get("archive_asset_url"),
            }
            changed = True
            enriched_entries += 1
        if changed:
            save_json(manifest_path, manifest)
            changed_manifests += 1
    print(f"enriched {enriched_entries} bundle entries in {changed_manifests} manifests")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("prepare")
    p.add_argument("--family")
    p.add_argument("--github-output", type=Path)
    p.set_defaults(func=prepare)

    p = sub.add_parser("enrich")
    p.add_argument("--index", type=int, required=True)
    p.add_argument("--expected-id")
    p.add_argument("--work-dir", type=Path, default=Path("work/auxiliary-matrix"))
    p.add_argument("--result-dir", type=Path, default=Path("_auxiliary_result"))
    p.set_defaults(func=enrich)

    p = sub.add_parser("merge")
    p.add_argument("--results-dir", type=Path, default=Path("_auxiliary_results"))
    p.set_defaults(func=merge)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
