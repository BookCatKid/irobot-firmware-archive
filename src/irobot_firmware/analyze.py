from __future__ import annotations

import hashlib
import mmap
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

from .util import save_json, sha256_file

# Qualcomm/iRobot OTA key-type mapping observed in signed sapphire packages.
KEY_TYPE_NAMES = {
    "A": "TZ",
    "B": "RPM",
    "C": "ABL",
    "D": "SYSTEM",
    "E": "KERNEL",
    "F": "STUBL",
    "G": "CMNLIB",
    "H": "CMNLIB64",
    "J": "DEVCFG",
    "K": "KM",
    "L": "PMIC",
    "M": "STORSEC",
    "N": "UEFI_SEC",
}

TEXT_SNAPSHOT_PATHS = {
    "opt/irobot/identity.env",
    "opt/irobot/version.env",
    "etc/os-release",
    "etc/issue",
    "etc/issue.net",
    "etc/version",
    "etc/build.prop",
    "build.prop",
}


def _ascii_strings(data: bytes, minimum: int = 4) -> list[str]:
    return [m.group().decode("ascii", "replace") for m in re.finditer(rb"[ -~]{%d,}" % minimum, data)]


def _find_otie_items(mm: mmap.mmap) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor = 0
    ordinal = 0
    while True:
        pos = mm.find(b"Otie", cursor)
        if pos < 0:
            break
        cursor = pos + 4
        # Valid observed frame: Otie <len:u32> indx <len=1:u32> <idx:u8> data <len:u32> <payload>
        if pos + 25 > len(mm) or mm[pos + 8 : pos + 12] != b"indx" or mm[pos + 17 : pos + 21] != b"data":
            continue
        total_len = struct.unpack_from("<I", mm, pos + 4)[0]
        index = mm[pos + 16]
        size = struct.unpack_from("<I", mm, pos + 21)[0]
        start = pos + 25
        end = start + size
        if size <= 0 or end > len(mm):
            continue
        prev = mm.rfind(b"Otim", max(0, pos - 32768), pos)
        meta_start = prev if prev >= 0 else max(0, pos - 8192)
        meta = bytes(mm[meta_start:pos])
        strings = _ascii_strings(meta)
        key_type = None
        match = re.search(rb"key type ([A-Z])", meta)
        if match:
            key_type = match.group(1).decode("ascii")
        expected_hash = None
        # Metadata uses a tiny TLV: 'hash' + little-endian length (32) + SHA-256 bytes.
        hpos = meta.rfind(b"hash")
        if hpos >= 0 and hpos + 8 <= len(meta):
            hlen = struct.unpack_from("<I", meta, hpos + 4)[0]
            if hlen == 32 and hpos + 8 + hlen <= len(meta):
                expected_hash = meta[hpos + 8 : hpos + 8 + hlen].hex()
        payload = memoryview(mm)[start:end]
        actual_hash = hashlib.sha256(payload).hexdigest()
        magic = bytes(payload[:16])
        kind = "binary"
        if magic.startswith(b"\x7fELF"):
            kind = "elf"
        elif magic.startswith(b"hsqs"):
            kind = "squashfs"
        elif magic.startswith(b"ANDROID!"):
            kind = "android-boot"
        useful = [
            s for s in strings
            if any(k in s.lower() for k in ("package", "firmware", "git_hash", "os_version", "product_version", "key type"))
        ]
        items.append({
            "ordinal": ordinal,
            "index": index,
            "key_type": key_type,
            "name": KEY_TYPE_NAMES.get(key_type or "", f"COMPONENT_{index}"),
            "kind": kind,
            "otie_offset": pos,
            "payload_offset": start,
            "size": size,
            "sha256": actual_hash,
            "metadata_sha256": expected_hash,
            "metadata_hash_verified": expected_hash == actual_hash if expected_hash else None,
            "magic": magic.hex(),
            "metadata_hints": useful[-12:],
            "_start": start,
            "_end": end,
            "_total_len": total_len,
        })
        ordinal += 1
    return items


def _file_manifest(root: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    files: list[dict[str, Any]] = []
    snapshots: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        try:
            if path.is_symlink():
                files.append({"path": rel, "type": "symlink", "target": os.readlink(path)})
            elif path.is_file():
                size = path.stat().st_size
                entry = {"path": rel, "type": "file", "size": size, "sha256": sha256_file(path)}
                files.append(entry)
                if rel in TEXT_SNAPSHOT_PATHS and size <= 256 * 1024:
                    try:
                        snapshots[rel] = path.read_text(errors="replace")
                    except Exception:
                        pass
            elif path.is_dir():
                files.append({"path": rel, "type": "dir"})
        except (FileNotFoundError, PermissionError):
            continue
    return files, snapshots


def _analyze_squashfs(blob: Path, work_dir: Path) -> dict[str, Any]:
    info: dict[str, Any] = {"filesystem": "squashfs", "extractable": False}
    unsquashfs = shutil.which("unsquashfs")
    if not unsquashfs:
        info["error"] = "unsquashfs not installed"
        return info
    root = work_dir / "rootfs"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    proc = subprocess.run(
        [unsquashfs, "-no-xattrs", "-f", "-d", str(root), str(blob)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    info["unsquashfs_exit"] = proc.returncode
    if proc.returncode not in (0, 2):  # macOS can return 2 only because device nodes cannot be created as non-root.
        info["error"] = proc.stdout[-4000:]
        return info
    manifest, snapshots = _file_manifest(root)
    info.update({
        "extractable": True,
        "file_count": sum(1 for x in manifest if x["type"] == "file"),
        "entry_count": len(manifest),
        "files": manifest,
        "text_snapshots": snapshots,
    })
    return info


def analyze(path: Path, output: Path, work_dir: Path, deep: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": 1,
        "filename": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "format": "unknown",
        "components": [],
    }
    work_dir.mkdir(parents=True, exist_ok=True)
    with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        if mm[:4] == b"Otps":
            result["format"] = "irobot-otps"
        items = _find_otie_items(mm)
        if items:
            result["format"] = "irobot-otps"
            for item in items:
                public = {k: v for k, v in item.items() if not k.startswith("_")}
                if deep and item["kind"] == "squashfs":
                    comp_path = work_dir / f"component-{item['index']:02d}.squashfs"
                    with comp_path.open("wb") as out:
                        out.write(mm[item["_start"] : item["_end"]])
                    public["filesystem_analysis"] = _analyze_squashfs(comp_path, work_dir / f"component-{item['index']:02d}")
                result["components"].append(public)
    save_json(output, result)
    return result
