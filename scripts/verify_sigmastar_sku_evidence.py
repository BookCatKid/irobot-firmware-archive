#!/usr/bin/env python3
"""Reproduce hardware/SKU observations from preserved modern iRobot OTA bytes.

Requires curl and unsquashfs. Each sample is a known, SHA-256-verified archive
asset; this tool does not probe or guess OTA filenames or firmware versions.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "data/research/sigmastar-embedded-sku-evidence-2026-11-10.json"


def _squashfs_offsets(blob: bytes):
    start = 0
    while (pos := blob.find(b"hsqs", start)) >= 0:
        start = pos + 4
        if pos + 96 > len(blob):
            continue
        major, minor = struct.unpack_from("<HH", blob, pos + 28)
        bytes_used = struct.unpack_from("<Q", blob, pos + 40)[0]
        if (major, minor) == (4, 0) and 96 <= bytes_used <= len(blob) - pos:
            yield pos


def _cat_squashfs(image: Path, offset: int, path: str) -> str:
    proc = subprocess.run(
        ["unsquashfs", "-cat", "-o", str(offset), str(image), path],
        capture_output=True, check=True,
    )
    return proc.stdout.decode("utf-8").strip()


def _ini_value(content: str, section: str, key: str) -> str:
    parsed = configparser.ConfigParser()
    parsed.read_string(content)
    return parsed[section][key]


def verify(record: dict, local_file: Path | None = None) -> dict:
    with tempfile.TemporaryDirectory(prefix="irobot-sku-") as tmp:
        package = local_file if local_file else Path(tmp) / "firmware.signed"
        if local_file is None:
            subprocess.run(
                ["curl", "--fail", "--location", "--silent", "--show-error",
                 "--retry", "2", "--max-time", "180", "--output", str(package),
                 record["source"]],
                check=True,
            )
        outer = package.read_bytes()
        digest = hashlib.sha256(outer).hexdigest()
        if digest != record["firmware_sha256"]:
            raise ValueError(f"{record['family']}: signed package SHA-256 differs: {digest}")
        if outer[:4] != b"aPKG" or outer[0x30:0x32] != b"\x1f\x8b":
            raise ValueError(f"{record['family']}: not the expected SigmaStar aPKG/gzip")
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        inner = inflater.decompress(outer[0x30:]) + inflater.flush()
        if not inflater.eof:
            raise ValueError(f"{record['family']}: incomplete gzip member")

        offsets = list(_squashfs_offsets(inner))
        if record["inner_squashfs_offset"] not in offsets:
            raise ValueError(f"{record['family']}: recorded SquashFS offset not found: {offsets}")
        image = Path(tmp) / "SStarOta.bin"
        image.write_bytes(inner)
        offset = record["inner_squashfs_offset"]
        version_data = _cat_squashfs(image, offset, "oem/sysconf/sysVersion.ini")
        sku_data = _cat_squashfs(image, offset, "oem/sysconf/product_sku.ini")
        sdk_data = _cat_squashfs(image, offset, "oem/irobot/conf/sdk_version.ini")
        observed = {
            "family": record["family"],
            "archive_sha256": digest,
            "sysProduct": _ini_value(version_data, "sysversion_Config", "sysProduct"),
            "sysVersion": _ini_value(version_data, "sysversion_Config", "sysVersion"),
            "sku_template": _ini_value(sku_data, "SKU_CONFIG", "product_sku"),
            "sdk_version": sdk_data,
        }
        expected = {
            "family": record["family"],
            "archive_sha256": record["firmware_sha256"],
            "sysProduct": record["embedded_sys_product"],
            "sysVersion": record["embedded_sys_version"],
            "sku_template": record["embedded_product_sku_template"],
            "sdk_version": record["embedded_sdk_version"],
        }
        if observed != expected:
            raise ValueError(f"Embedded identity differs: {observed!r} != {expected!r}")
        return observed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", help="Verify only this recorded family")
    parser.add_argument("--local-file", type=Path, help="Existing .signed file (requires --family)")
    args = parser.parse_args()
    if args.local_file and not args.family:
        parser.error("--local-file requires --family")
    for name in ("curl", "unsquashfs"):
        if shutil.which(name) is None:
            parser.error(f"Required executable not found: {name}")
    records = json.loads(EVIDENCE.read_text())["verified_images"]
    selected = [r for r in records if not args.family or r["family"] == args.family]
    if not selected:
        parser.error(f"No recorded evidence for family {args.family!r}")
    for record in selected:
        print(json.dumps(verify(record, args.local_file), sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
