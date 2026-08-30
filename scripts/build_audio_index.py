#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.audio import build_audio_index
from irobot_firmware.catalog import load_catalog


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Index audio assets embedded in deeply analyzed iRobot firmware filesystems"
    )
    parser.add_argument("--catalog", type=Path, default=Path("data/catalog.json"))
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--output", type=Path, default=Path("data/audio-assets.json"))
    args = parser.parse_args()

    index = build_audio_index(load_catalog(args.catalog), args.data_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    summary = index["summary"]
    print(
        f"indexed {summary['audio_file_occurrence_count']} audio occurrences "
        f"({summary['unique_sha256_count']} unique SHA-256), "
        f"{summary['language_count']} languages, {summary['unique_song_name_count']} song names"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
