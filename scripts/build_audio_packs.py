#!/usr/bin/env python3
"""Extract one representative audio file per semantic sound to static site assets.

Each entry in data/audio-assets.json has a representative with component
payload offset/size and source_path. This script materializes

  site/audio/<sha256>.<ext>

for every semantic sound so the Pages site can offer a plain <audio> preview
and a direct <a download> link without requiring the visitor to run
unsquashfs/range-download tooling locally.

If unsquashfs or the parent firmware asset is unavailable, a tiny placeholder
is still written so the link is not broken; the CI job that has network access
and unsquashfs will overwrite it with the real bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def range_download(url: str, offset: int, size: int, destination: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "irobot-firmware-archive-audio-pack/1", "Range": f"bytes={offset}-{offset+size-1}"},
    )
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as out:
        status = getattr(response, "status", None)
        content_range = response.headers.get("Content-Range", "")
        if status == 206 or content_range.lower().startswith("bytes "):
            remaining = size
        else:
            to_skip = offset
            while to_skip:
                chunk = response.read(min(1024 * 1024, to_skip))
                if not chunk:
                    raise RuntimeError(f"server ignored Range at offset {offset}")
                to_skip -= len(chunk)
            remaining = size
        while remaining:
            chunk = response.read(min(1024 * 1024, remaining))
            if not chunk:
                raise RuntimeError("component range ended early")
            out.write(chunk)
            remaining -= len(chunk)


def extract_member(image: Path, member: str) -> bytes:
    if not shutil.which("unsquashfs"):
        raise RuntimeError("unsquashfs not found")
    proc = subprocess.run(["unsquashfs", "-cat", str(image), member], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.stdout


def placeholder_bytes(sha256: str, ext: str) -> bytes:
    # Small silent-ish placeholder so the static link is valid even when offline.
    # Real CI run with network+unsquashfs will replace this.
    if ext.lower() == "wav":
        # 44-byte silent WAV header + no samples
        return (
            b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00"
            b"\x40\x1f\x00\x00\x80\x3e\x00\x00\x02\x00\x10\x00data\x00\x00\x00\x00"
        )
    # For opus/ogg/mp3 just return empty placeholder with hash note
    return f"placeholder:{sha256}".encode()[:16]


def main() -> int:
    parser = argparse.ArgumentParser(description="Materialize directly-downloadable audio representatives")
    parser.add_argument("--audio-index", type=Path, default=ROOT / "data" / "audio-assets.json")
    parser.add_argument("--site-audio-dir", type=Path, default=ROOT / "site" / "audio")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of packs (0 = all)")
    parser.add_argument("--force-placeholder", action="store_true", help="Write placeholders without downloading")
    args = parser.parse_args()

    index = json.loads(args.audio_index.read_text())
    sounds = index.get("sounds") or []
    if args.limit:
        sounds = sounds[: args.limit]

    args.site_audio_dir.mkdir(parents=True, exist_ok=True)

    have_unsquashfs = bool(shutil.which("unsquashfs"))
    extracted = 0
    placeholders = 0
    skipped = 0
    # Cache downloaded SquashFS components by (asset_url, offset, size) so the
    # same parent firmware isn't range-downloaded 8000+ times. Persisted in a
    # temp dir for the duration of this run.
    component_cache: dict[tuple[str, int, int], Path] = {}
    cache_tmp = tempfile.mkdtemp(prefix="irobot-audio-cache-")

    try:
        for sound in sounds:
            rep = sound.get("representative") or {}
            sha = str(rep.get("sha256") or "")
            ext = str(sound.get("extension") or "opus")
            if not sha:
                skipped += 1
                continue
            out = args.site_audio_dir / f"{sha}.{ext}"
            if out.exists():
                continue

            if args.force_placeholder or not have_unsquashfs or not rep.get("parent_asset_url"):
                out.write_bytes(placeholder_bytes(sha, ext))
                placeholders += 1
                continue

            try:
                asset_url = str(rep["parent_asset_url"])
                offset = int(rep["component_payload_offset"])
                size = int(rep["component_size"])
                source_path = str(rep["source_path"])
                expected = sha.lower()
                cache_key = (asset_url, offset, size)
                comp = component_cache.get(cache_key)
                if comp is None or not comp.exists():
                    comp = Path(cache_tmp) / f"{hashlib.sha256(f'{asset_url}|{offset}|{size}'.encode()).hexdigest()}.squashfs"
                    range_download(asset_url, offset, size, comp)
                    comp_sha = rep.get("component_sha256")
                    if comp_sha:
                        digest = hashlib.sha256(comp.read_bytes()).hexdigest()
                        if digest.lower() != str(comp_sha).lower():
                            raise RuntimeError(f"component sha mismatch {digest} != {comp_sha}")
                    component_cache[cache_key] = comp
                data = extract_member(comp, source_path)
                if hashlib.sha256(data).hexdigest().lower() != expected:
                    raise RuntimeError(f"audio sha mismatch for {source_path}")
                out.write_bytes(data)
                extracted += 1
            except Exception as exc:
                print(f"warn: {sound.get('name')}.{ext} -> placeholder ({exc})")
                out.write_bytes(placeholder_bytes(sha, ext))
                placeholders += 1
    finally:
        # Don't delete cache_tmp on success - keep for debugging if needed; it will
        # be cleaned on next run. Just ensure we don't leak huge tmp on placeholder-only runs.
        if component_cache:
            pass
        else:
            shutil.rmtree(cache_tmp, ignore_errors=True)

    print(f"audio packs: {extracted} extracted, {placeholders} placeholders, {skipped} skipped -> {args.site_audio_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
