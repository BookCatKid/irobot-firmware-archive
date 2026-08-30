#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.catalog import load_catalog
from irobot_firmware.integrity import audit_release_assets


def github_releases(repo: str) -> list[dict]:
    proc = subprocess.run(
        ["gh", "api", "--paginate", "--slurp", f"repos/{repo}/releases?per_page=100"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    pages = json.loads(proc.stdout)
    releases: list[dict] = []
    for page in pages:
        if isinstance(page, list):
            releases.extend(page)
        elif isinstance(page, dict):
            releases.append(page)
    return releases


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify archived firmware bytes against GitHub Release SHA-256 digests")
    parser.add_argument("--repo", default="BookCatKid/irobot-firmware-archive")
    parser.add_argument("--catalog", type=Path, default=Path("data/catalog.json"))
    args = parser.parse_args()

    result = audit_release_assets(load_catalog(args.catalog), github_releases(args.repo))
    print(
        f"verified {result['firmware_checked']} firmware assets and "
        f"{result['metapackages_checked']} distinct metapackages; "
        f"issues={result['issue_count']}"
    )
    for issue in result["issues"]:
        print("ERROR", json.dumps(issue, sort_keys=True))
    return 1 if result["issues"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
