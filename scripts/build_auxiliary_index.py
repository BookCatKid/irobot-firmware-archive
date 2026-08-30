#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.auxiliary import build_auxiliary_index
from irobot_firmware.catalog import load_catalog


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Index aux-board firmware bundles embedded in archived iRobot firmware filesystems"
    )
    parser.add_argument("--catalog", type=Path, default=Path("data/catalog.json"))
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--output", type=Path, default=Path("data/auxiliary-firmware.json"))
    args = parser.parse_args()

    index = build_auxiliary_index(load_catalog(args.catalog), args.data_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    summary = index["summary"]
    print(
        f"indexed {summary['bundle_count']} auxiliary bundles "
        f"({summary['unique_sha256_count']} unique SHA-256) across "
        f"{len(summary['families'])} families"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
