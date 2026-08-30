from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .archive import archive_blob, archive_one
from .backfill import classic_versions, numeric_versions, scan_direct, semantic_versions
from .catalog import load_catalog, merge_records, write_catalog
from .discover import discover_from_config
from .util import load_json
from datetime import datetime, timezone

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
    elif args.scheme == "semantic":
        versions = semantic_versions(args.major_max, args.minor_max, args.patch_max)
    else:
        versions = numeric_versions(args.numeric_start, args.numeric_end, args.numeric_width)
    hits = scan_direct(args.family, args.template, versions, args.workers, args.max_probes, args.pause)
    if args.scheme == "numeric" and args.version_prefix:
        for hit in hits:
            token = hit["version"]
            hit["filename_token"] = f"{args.version_prefix}{token}"
            hit["version"] = f"{args.version_prefix}{token}"
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
    existing_by_sha = {
        x.get("archive", {}).get("sha256"): x.get("archive")
        for x in catalog.get("firmwares", [])
        if x.get("archive", {}).get("sha256")
    }
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
            existing_by_sha=existing_by_sha,
        )
        if item.get("archive", {}).get("sha256"):
            existing_by_sha[item["archive"]["sha256"]] = item["archive"]
        write_catalog(args.catalog, catalog)
    return 0


def cmd_import_file(args: argparse.Namespace) -> int:
    if not args.path.is_file():
        raise SystemExit(f"file not found: {args.path}")
    if not args.repo and not args.no_upload:
        raise SystemExit("--repo OWNER/REPO is required unless --no-upload")
    source_url = args.source_url or f"app-embedded://{args.source_package or 'unknown'}/{args.source_app_version or 'unknown'}/{args.source_resource or args.path.name}"
    record = {
        "family": args.family,
        "version": args.version,
        "url": source_url,
        "source": args.source,
        "source_package": args.source_package,
        "source_app_version": args.source_app_version,
        "source_resource": args.source_resource,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
        "track": args.track,
    }
    catalog = load_catalog(args.catalog)
    catalog, _ = merge_records(catalog, [record])
    item = next(x for x in catalog["firmwares"] if x.get("family") == args.family and x.get("version") == args.version and x.get("url") == source_url)
    item["archive"] = archive_blob(item, args.path, args.repo or "local/no-upload", Path("data"), args.work_dir, upload_release=not args.no_upload, deep=not args.shallow)
    write_catalog(args.catalog, catalog)
    print(json.dumps(item, indent=2))
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
    backfill.add_argument("--scheme", choices=["classic", "semantic", "numeric"], default="classic")
    backfill.add_argument("--year-start", type=int, default=17)
    backfill.add_argument("--year-end", type=int, default=26)
    backfill.add_argument("--major-max", type=int, default=15)
    backfill.add_argument("--minor-max", type=int, default=60)
    backfill.add_argument("--patch-max", type=int, default=15)
    backfill.add_argument("--numeric-start", type=int, default=0)
    backfill.add_argument("--numeric-end", type=int, default=9999)
    backfill.add_argument("--numeric-width", type=int, default=0)
    backfill.add_argument("--version-prefix", default="", help="prefix numeric catalog versions, e.g. v -> v2444")
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

    imp = sub.add_parser("import-file", help="archive a firmware payload obtained outside the OTA downloader (for example embedded in an official app)")
    imp.add_argument("path", type=Path)
    imp.add_argument("--family", required=True)
    imp.add_argument("--version", required=True)
    imp.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY"))
    imp.add_argument("--source", default="app-embedded")
    imp.add_argument("--source-package")
    imp.add_argument("--source-app-version")
    imp.add_argument("--source-resource")
    imp.add_argument("--source-url")
    imp.add_argument("--track", default="app-bundled")
    imp.add_argument("--no-upload", action="store_true")
    imp.add_argument("--shallow", action="store_true")
    imp.add_argument("--work-dir", type=Path, default=Path("work"))
    imp.set_defaults(func=cmd_import_file)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
