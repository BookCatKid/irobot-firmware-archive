#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.analyze import AUXILIARY_BUNDLE_MARKER, _analyze_auxiliary_bundle
from irobot_firmware.util import save_json, sha256_file


def walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enrich tracked manifests from exact aux-board bundle bytes retained under work/"
    )
    parser.add_argument("--work-dir", type=Path, default=Path("work"))
    parser.add_argument("--firmware-dir", type=Path, default=Path("data/firmware"))
    args = parser.parse_args()

    local: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(args.work_dir.glob("**/rootfs/**/auxboard_firmware*")):
        if not path.is_file():
            continue
        sha = sha256_file(path)
        local.setdefault(sha, (path, _analyze_auxiliary_bundle(path)))
    print(f"local exact auxiliary bundles: {len(local)}")

    changed_files = 0
    enriched_entries = 0
    for manifest_path in sorted(args.firmware_dir.rglob("*.json")):
        try:
            data = json.loads(manifest_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        changed = False
        for node in walk(data):
            path = node.get("path")
            sha = node.get("sha256")
            if not isinstance(path, str) or AUXILIARY_BUNDLE_MARKER not in path.lower():
                continue
            if not isinstance(sha, str) or sha not in local:
                continue
            local_path, analysis = local[sha]
            if node.get("auxiliary_firmware") == analysis:
                continue
            # The manifest hash is the trust join: only attach nested analysis when
            # the locally retained bundle is byte-for-byte the file already hashed
            # in the archived parent filesystem manifest.
            if sha256_file(local_path) != sha:
                raise RuntimeError(f"hash changed while reading {local_path}")
            node["auxiliary_firmware"] = analysis
            node["auxiliary_firmware_provenance"] = {
                "method": "exact-sha256-matched-local-deep-analysis",
                "bundle_sha256": sha,
            }
            changed = True
            enriched_entries += 1
        if changed:
            save_json(manifest_path, data)
            changed_files += 1
            print(f"enriched {manifest_path}")

    print(f"enriched entries: {enriched_entries}; manifest files: {changed_files}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
