#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.archive import archive_metapackage, refresh_release_notes
from irobot_firmware.catalog import load_catalog, write_catalog
from irobot_firmware.download import download


def colliding_records(catalog: dict) -> list[dict]:
    """Return records whose distinct metapackage reused the firmware asset URL."""
    out = []
    seen_tags: set[str] = set()
    for record in catalog.get("firmwares", []):
        archive = record.get("archive") or {}
        meta = archive.get("metapackage") or {}
        tag = str(archive.get("release_tag") or "")
        if not tag or tag in seen_tags:
            continue
        if (
            meta
            and not meta.get("same_as_firmware")
            and meta.get("sha256") != archive.get("sha256")
            and meta.get("asset_url") == archive.get("asset_url")
        ):
            out.append(record)
            seen_tags.add(tag)
    return out


def repair_record(record: dict, repo: str, data_root: Path, work_root: Path) -> None:
    archive = record["archive"]
    tag = str(archive["release_tag"])
    expected_sha = str(archive["sha256"])
    expected_size = int(archive["size"])
    filename = Path(urllib.parse.urlsplit(str(record["url"])).path).name
    if not filename:
        raise RuntimeError(f"cannot derive firmware filename for {tag}")

    repair_dir = work_root / "metapackage-collision-repair" / tag
    blob = repair_dir / filename
    result = download(str(record["url"]), blob, expected_size=expected_size)
    if result["sha256"] != expected_sha:
        raise RuntimeError(
            f"firmware SHA-256 mismatch for {tag}: expected {expected_sha}, "
            f"got {result['sha256']}"
        )

    # Restore the original firmware bytes first. The patched metapackage archiver
    # then uses a namespaced Release asset if its source basename is identical.
    subprocess.run(
        ["gh", "release", "upload", tag, str(blob), "--repo", repo, "--clobber"],
        check=True,
    )
    meta = archive_metapackage(
        record,
        archive,
        repo,
        data_root,
        work_root,
        upload_release=True,
    )
    if not meta:
        raise RuntimeError(f"missing metapackage while repairing {tag}")
    archive["metapackage"] = meta
    refresh_release_notes(record, repo, data_root, work_root)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Repair GitHub Release assets where a distinct signed metapackage "
            "clobbered firmware bytes because both source URLs used the same basename"
        )
    )
    parser.add_argument("--repo", required=True)
    parser.add_argument("--catalog", type=Path, default=Path("data/catalog.json"))
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--work-dir", type=Path, default=Path("work"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    catalog = load_catalog(args.catalog)
    records = colliding_records(catalog)
    print(f"colliding releases: {len(records)}", flush=True)
    for record in records:
        archive = record["archive"]
        print(
            f"REPAIR {record.get('family')} {record.get('version')} "
            f"{archive.get('release_tag')}",
            flush=True,
        )
        if args.dry_run:
            continue
        repair_record(record, args.repo, args.data_root, args.work_dir)
        # Persist after each release so an interrupted repair is safely resumable.
        write_catalog(args.catalog, catalog)

    if not args.dry_run:
        write_catalog(args.catalog, catalog)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
