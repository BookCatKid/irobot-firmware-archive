#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.archive import archive_metapackage, refresh_release_notes
from irobot_firmware.catalog import load_catalog, write_catalog


def main() -> int:
    parser = argparse.ArgumentParser(description="Preserve signed metapackages for already archived firmware records")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--catalog", type=Path, default=Path("data/catalog.json"))
    parser.add_argument("--work-dir", type=Path, default=Path("work"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    catalog = load_catalog(args.catalog)
    candidates = [
        r for r in catalog.get("firmwares", [])
        if r.get("metapackage_url") and r.get("archive") and not (r.get("archive") or {}).get("metapackage")
    ]
    print(f"metapackages pending: {len(candidates)}")
    for record in candidates:
        print(f"META {record.get('family')} {record.get('version')} {record.get('metapackage_url')}", flush=True)
        if args.dry_run:
            continue
        meta = archive_metapackage(record, record["archive"], args.repo, Path("data"), args.work_dir, upload_release=True)
        if meta:
            record["archive"]["metapackage"] = meta
            write_catalog(args.catalog, catalog)
            refresh_release_notes(record, args.repo, Path("data"), args.work_dir)
    if not args.dry_run:
        write_catalog(args.catalog, catalog)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
