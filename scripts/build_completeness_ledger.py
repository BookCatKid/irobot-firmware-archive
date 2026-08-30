#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.catalog import load_catalog
from irobot_firmware.completeness import build_completeness_ledger
from irobot_firmware.util import load_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the evidence-based firmware completeness ledger")
    parser.add_argument("--catalog", type=Path, default=Path("data/catalog.json"))
    parser.add_argument("--platforms", type=Path, default=Path("config/platforms.json"))
    parser.add_argument("--research-root", type=Path, default=Path("data/research"))
    parser.add_argument("--output", type=Path, default=Path("data/completeness.json"))
    args = parser.parse_args()
    ledger = build_completeness_ledger(load_catalog(args.catalog), load_json(args.platforms, {}), args.research_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n")
    summary = ledger["summary"]
    print(
        f"{summary['unique_recovered_artifact_sha256_count']} unique recovered artifacts; "
        f"{summary['historical_state_only_count']} historical state-only leads; "
        f"{summary['independently_proven_missing_ota_artifact_count']} independently proven missing OTA artifacts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
