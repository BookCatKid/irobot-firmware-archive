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


def _parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        if key and value:
            values[key.strip()] = value
    return values


def _version_prefix(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"(?:^|\+)(\d+(?:\.\d+){1,3})(?:\+|$)", value)
    return match.group(1) if match else None


def _extract_reported_identity(components: list[dict[str, Any]]) -> dict[str, Any]:
    """Recover authoritative product/version identity from extracted filesystems.

    Compact legacy OTA filenames can be ambiguous (for example ``lewis3126``).
    The filesystem itself is authoritative, so preserve both the source evidence
    and normalized version rather than guessing how a compact token is segmented.
    """
    snapshots: dict[str, str] = {}
    sources: dict[str, str] = {}
    for component in components:
        fs = component.get("filesystem_analysis") or {}
        for path, text in (fs.get("text_snapshots") or {}).items():
            if path not in snapshots:
                snapshots[path] = text
                sources[path] = str(component.get("name") or "unknown")

    identity = _parse_env(snapshots.get("opt/irobot/identity.env", ""))
    version_env = _parse_env(snapshots.get("opt/irobot/version.env", ""))
    build_prop = _parse_env(snapshots.get("build.prop", ""))
    if not build_prop:
        build_prop = _parse_env(snapshots.get("etc/build.prop", ""))
    os_release = _parse_env(snapshots.get("etc/os-release", ""))

    product_version = identity.get("PRODUCT_VERSION") or version_env.get("PRODUCT_VERSION")
    software_version = (
        build_prop.get("ro.build.version.release")
        or os_release.get("VERSION_ID")
        or os_release.get("VERSION")
        or product_version
    )
    normalized_version = _version_prefix(product_version) or _version_prefix(software_version)
    model = identity.get("MODEL") or version_env.get("MODEL")
    os_version = version_env.get("OS_VERSION")

    result = {
        "model": model,
        "version": normalized_version,
        "product_version": product_version,
        "software_version": software_version,
        "os_version": os_version,
    }
    result = {k: v for k, v in result.items() if v not in (None, "")}
    if result:
        result["evidence"] = {
            path: sources[path]
            for path in (
                "opt/irobot/identity.env",
                "opt/irobot/version.env",
                "build.prop",
                "etc/build.prop",
                "etc/os-release",
            )
            if path in snapshots
        }
    return result


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



def _analyze_apkg_header(mm: mmap.mmap) -> dict[str, Any]:
    """Parse the legacy iRobot ``aPKG`` container header conservatively.

    Multiple real Marconi samples show a fixed 0x58-byte table entry beginning at
    0x34.  Each entry contains an integer id, an absolute payload offset, a payload
    size, and a NUL-padded ASCII label.  We expose only fields that are validated
    against the file bounds; unknown top-level integers remain named as raw header
    values rather than assigning undocumented semantics.
    """
    if len(mm) < 0x34 or mm[:4] != b"aPKG":
        return {}

    name_raw = bytes(mm[16:48]).split(b"\0", 1)[0]
    entry_count = struct.unpack_from("<I", mm, 0x30)[0]
    entries: list[dict[str, Any]] = []
    entry_size = 0x58
    table_start = 0x34

    # Bound the count so malformed input cannot turn into a huge parse loop.
    if entry_count <= 64 and table_start + entry_count * entry_size <= len(mm):
        for ordinal in range(entry_count):
            pos = table_start + ordinal * entry_size
            entry_id, offset, size = struct.unpack_from("<III", mm, pos)
            label_raw = bytes(mm[pos + 12 : pos + entry_size]).split(b"\0", 1)[0]
            valid = size > 0 and offset >= table_start + entry_count * entry_size and offset + size <= len(mm)
            item: dict[str, Any] = {
                "ordinal": ordinal,
                "id": entry_id,
                "offset": offset,
                "size": size,
                "label": label_raw.decode("ascii", "replace"),
                "bounds_valid": valid,
            }
            if valid:
                payload = memoryview(mm)[offset : offset + size]
                item["sha256"] = hashlib.sha256(payload).hexdigest()
                item["magic"] = bytes(payload[:16]).hex()
            entries.append(item)

    raw_end = struct.unpack_from("<I", mm, 8)[0]
    trailer = len(mm) - raw_end if 0 <= raw_end <= len(mm) else None
    return {
        "magic": "aPKG",
        "container_version": struct.unpack_from("<I", mm, 4)[0],
        "header_u32_08": raw_end,
        "header_u32_0c": struct.unpack_from("<I", mm, 12)[0],
        "name_hint": name_raw.decode("ascii", "replace"),
        "entry_count": entry_count,
        "entries": entries,
        "trailing_bytes_after_header_u32_08": trailer,
    }

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
        elif mm[:4] == b"aPKG":
            result["format"] = "irobot-apkg"
            result["legacy_container"] = _analyze_apkg_header(mm)
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
            reported_identity = _extract_reported_identity(result["components"])
            if reported_identity:
                result["reported_identity"] = reported_identity
    save_json(output, result)
    return result
