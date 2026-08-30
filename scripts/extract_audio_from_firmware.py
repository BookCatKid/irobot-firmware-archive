#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path


def range_download(url: str, offset: int, size: int, destination: Path) -> None:
    if offset < 0 or size <= 0:
        raise ValueError("component offset/size must be positive")
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "irobot-firmware-archive-audio-extractor/1",
            "Range": f"bytes={offset}-{offset + size - 1}",
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as out:
        status = getattr(response, "status", None)
        content_range = response.headers.get("Content-Range", "")

        # GitHub/CDN paths normally honor Range with 206. Some mirrors/proxies
        # can ignore it and return the complete parent firmware with 200. In
        # that case stream-discard exactly ``offset`` bytes, then copy only the
        # requested SquashFS component instead of downloading/storing the whole
        # parent asset.
        if status == 206 or content_range.lower().startswith("bytes "):
            remaining = size
        else:
            to_skip = offset
            while to_skip:
                chunk = response.read(min(1024 * 1024, to_skip))
                if not chunk:
                    raise RuntimeError(
                        f"server ignored Range and ended while skipping to component offset {offset}"
                    )
                to_skip -= len(chunk)
            remaining = size

        while remaining:
            chunk = response.read(min(1024 * 1024, remaining))
            if not chunk:
                raise RuntimeError(f"component range ended early with {remaining} bytes remaining")
            out.write(chunk)
            remaining -= len(chunk)
    actual = destination.stat().st_size
    if actual != size:
        raise RuntimeError(f"component range returned {actual} bytes; expected {size}")


def extract_member(image: Path, member: str) -> bytes:
    if not shutil.which("unsquashfs"):
        raise RuntimeError("unsquashfs is required (macOS: brew install squashfs)")
    proc = subprocess.run(
        ["unsquashfs", "-cat", str(image), member],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc.stdout


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract one hash-verified embedded audio file from an archived iRobot firmware component"
    )
    parser.add_argument("--asset-url", required=True)
    parser.add_argument("--component-offset", type=int, required=True)
    parser.add_argument("--component-size", type=int, required=True)
    parser.add_argument("--component-sha256")
    parser.add_argument("--path", required=True, help="Path inside the SquashFS filesystem")
    parser.add_argument("--sha256", required=True, help="Expected SHA-256 of the extracted audio file")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    output = args.output or Path(args.path).name
    output = Path(output)
    expected_audio = args.sha256.lower()

    with tempfile.TemporaryDirectory(prefix="irobot-audio-") as td:
        component = Path(td) / "component.squashfs"
        range_download(args.asset_url, args.component_offset, args.component_size, component)
        if args.component_sha256:
            digest = hashlib.sha256(component.read_bytes()).hexdigest()
            if digest.lower() != args.component_sha256.lower():
                raise RuntimeError(
                    f"component SHA-256 mismatch: expected {args.component_sha256}, got {digest}"
                )
        audio = extract_member(component, args.path)

    digest = hashlib.sha256(audio).hexdigest()
    if digest != expected_audio:
        raise RuntimeError(f"audio SHA-256 mismatch: expected {expected_audio}, got {digest}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(audio)
    print(f"wrote {output} ({len(audio)} bytes, sha256={digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
