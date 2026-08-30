from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .archive import archive_one
from .backfill import classic_versions, scan_direct, semantic_versions
from .catalog import load_catalog, merge_records, write_catalog
from .discover import discover_from_config
from .util import load_json

ROOT = Path.cwd()
DEFAULT_CATALOG = Path("data/catalog.json")


def cmd_discover(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    records, errors = discover_from_config(args.config)
    catalog, added = merge_records(catalog, records)
    write_catalog(args.catalog, catalog)
    print(json.dumps({"discovered": len(records), "new": added, "errors": errors}, indent=2))
    return 0


def cmd_backfill(args: argparse.Namespace) -> int:
    if args.scheme == "classic":
        versions = classic_versions(args.year_start, args.year_end, args.patch_max)
    else:
        versions = semantic_versions(args.major_max, args.minor_max, args.patch_max)
    hits = scan_direct(args.family, args.template, versions, args.workers, args.max_probes, args.pause)
    catalog = load_catalog(args.catalog)
    catalog, added = merge_records(catalog, hits)
    write_catalog(args.catalog, catalog)
    print(json.dumps({"hits": len(hits), "new": added}, indent=2))
    return 0


def cmd_archive(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    pending = [x for x in catalog.get("firmwares", []) if not x.get("archive")]
    if args.family:
        pending = [x for x in pending if x.get("family") == args.family]
    if args.version:
        pending = [x for x in pending if x.get("version") == args.version]
    if args.limit:
        pending = pending[: args.limit]
    print(f"pending: {len(pending)}")
    if args.dry_run:
        for item in pending:
            print(f"DRY {item['family']} {item['version']} {item['url']}")
        return 0
    if not args.repo:
        raise SystemExit("--repo OWNER/REPO is required unless --dry-run")
    for item in pending:
        print(f"ARCHIVE {item['family']} {item['version']}", flush=True)
        item["archive"] = archive_one(
            item,
            args.repo,
            Path("data"),
            args.work_dir,
            upload_release=not args.no_upload,
            deep=not args.shallow,
        )
        write_catalog(args.catalog, catalog)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="irobot-fw", description="iRobot firmware discovery/archive tooling")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    sub = parser.add_subparsers(dest="command", required=True)

    discover = sub.add_parser("discover", help="query configured iRobot firmware sources")
    discover.add_argument("--config", type=Path, default=Path("config/discovery.json"))
    discover.set_defaults(func=cmd_discover)

    backfill = sub.add_parser("backfill", help="probe historical version space; intentionally manual")
    backfill.add_argument("--family", required=True)
    backfill.add_argument("--template", required=True, help="URL template containing {family} and {version}")
    backfill.add_argument("--scheme", choices=["classic", "semantic"], default="classic")
    backfill.add_argument("--year-start", type=int, default=17)
    backfill.add_argument("--year-end", type=int, default=26)
    backfill.add_argument("--major-max", type=int, default=15)
    backfill.add_argument("--minor-max", type=int, default=60)
    backfill.add_argument("--patch-max", type=int, default=15)
    backfill.add_argument("--workers", type=int, default=4)
    backfill.add_argument("--pause", type=float, default=0.0)
    backfill.add_argument("--max-probes", type=int)
    backfill.set_defaults(func=cmd_backfill)

    archive = sub.add_parser("archive", help="download pending catalog entries, analyze, optionally upload release assets")
    archive.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY"))
    archive.add_argument("--family")
    archive.add_argument("--version")
    archive.add_argument("--limit", type=int)
    archive.add_argument("--dry-run", action="store_true")
    archive.add_argument("--no-upload", action="store_true")
    archive.add_argument("--shallow", action="store_true", help="skip SquashFS extraction/file hashing")
    archive.add_argument("--work-dir", type=Path, default=Path("work"))
    archive.set_defaults(func=cmd_archive)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
