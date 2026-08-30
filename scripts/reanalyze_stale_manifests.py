#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import urllib.parse
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.analyze import analyze
from irobot_firmware.archive import refresh_release_notes
from irobot_firmware.catalog import load_catalog, write_catalog
from irobot_firmware.download import download


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Re-run the current parser over archived firmware whose tracked manifest is still format=unknown"
    )
    parser.add_argument("--repo", default="BookCatKid/irobot-firmware-archive")
    parser.add_argument("--catalog", type=Path, default=Path("data/catalog.json"))
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--work-root", type=Path, default=Path("work/stale-manifest-reanalysis"))
    parser.add_argument("--no-upload", action="store_true")
    args = parser.parse_args()

    catalog = load_catalog(args.catalog)
    groups: dict[str, list[dict]] = defaultdict(list)
    for record in catalog.get("firmwares") or []:
        archive = record.get("archive") or {}
        if archive.get("format") == "unknown" and archive.get("sha256") and archive.get("asset_url"):
            groups[str(archive["sha256"])].append(record)

    print(f"stale rows {sum(map(len, groups.values()))}; unique payloads {len(groups)}")
    args.work_root.mkdir(parents=True, exist_ok=True)
    for sha, records in groups.items():
        canonical = next((r for r in records if not (r.get("archive") or {}).get("deduplicated")), records[0])
        archive = canonical["archive"]
        tag = str(archive.get("release_tag") or "")
        asset_url = str(archive["asset_url"])
        asset_name = urllib.parse.unquote(Path(urllib.parse.urlsplit(asset_url).path).name)
        group_work = args.work_root / sha[:12]
        if group_work.exists():
            shutil.rmtree(group_work)
        group_work.mkdir(parents=True)
        blob = group_work / asset_name
        print(f"ANALYZE {canonical.get('family')} {canonical.get('version')} {sha[:12]} {asset_name}")
        result = download(asset_url, blob, int(archive.get("size") or 0))
        if result["sha256"] != sha:
            raise RuntimeError(f"SHA-256 mismatch for {asset_url}: expected {sha}, got {result['sha256']}")

        # Deep=False is intentional: this migration repairs stale top-level parser
        # metadata without re-extracting hundreds of MB of filesystems. Existing
        # deep manifests remain untouched; future archival still performs deep analysis.
        temporary_manifest = group_work / "analysis.json"
        analysis = analyze(blob, temporary_manifest, group_work / "analysis", deep=False)
        print(f"  -> {analysis.get('format')}")
        for record in records:
            row_archive = record["archive"]
            manifest_rel = row_archive.get("manifest")
            if not manifest_rel:
                continue
            manifest_path = args.data_root / str(manifest_rel)
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(temporary_manifest.read_text())
            row_archive["format"] = analysis.get("format")
            row_archive["component_count"] = len(analysis.get("components") or [])
            metapackage = row_archive.get("metapackage") or {}
            if (
                metapackage.get("same_as_firmware") is True
                and metapackage.get("sha256") == row_archive.get("sha256")
            ):
                # Legacy V1 sometimes exposes the exact same bytes through both
                # /package/ and /metapackage/ endpoints. Keep that alias metadata
                # in sync with the verified firmware analysis.
                metapackage["format"] = analysis.get("format")
                metapackage["manifest"] = manifest_rel
            if analysis.get("reported_identity"):
                row_archive["reported_identity"] = analysis["reported_identity"]
            else:
                row_archive.pop("reported_identity", None)
            if not args.no_upload and tag:
                subprocess.run(
                    ["gh", "release", "upload", tag, str(manifest_path), "--repo", args.repo, "--clobber"],
                    check=True,
                )
        if not args.no_upload and tag:
            refresh_release_notes(canonical, args.repo, args.data_root, args.work_root / "release-notes")
        write_catalog(args.catalog, catalog)
        shutil.rmtree(group_work, ignore_errors=True)

    shutil.rmtree(args.work_root, ignore_errors=True)
    remaining = sum(
        1 for record in catalog.get("firmwares") or []
        if (record.get("archive") or {}).get("format") == "unknown"
    )
    print(f"remaining unknown rows: {remaining}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
