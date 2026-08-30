from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
from typing import Any, Iterable

from .util import load_json


AUXILIARY_BUNDLE_MARKER = "auxboard_firmware"
IMAGE_LINE_RE = re.compile(r"^IMAGE\s+(\d+)\s+(\S+)\s+(.+?)\s*$", re.MULTILINE)
MD5_LINE_RE = re.compile(r"^MD5SUM\s+([0-9a-fA-F]{32})\s*$", re.MULTILINE)
DOCK_DESCRIPTOR_RE = re.compile(r"\[\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\]")


def _payload_role(path: str) -> str:
    lower = path.lower()
    if "dock" in lower:
        return "dock"
    if "confinement" in lower or "beacon" in lower:
        return "confinement"
    if "mobility" in lower or "_mob" in lower or "/mob" in lower:
        return "mobility"
    if "safety" in lower or "_sft" in lower or "/sft" in lower:
        return "safety"
    if "power" in lower or "_pwr" in lower or "/pwr" in lower:
        return "power"
    return "auxiliary"


def _descriptor_key(path: str) -> str:
    name = Path(path).name.lower()
    for suffix in (".pkg.enc", ".bin.enc", ".enc", ".txt"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _node_metadata(members: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, list[int]]]:
    images: dict[str, dict[str, Any]] = {}
    dock_versions: dict[str, list[int]] = {}
    for member in members:
        text = member.get("text")
        if not isinstance(text, str):
            continue
        for match in IMAGE_LINE_RE.finditer(text):
            image = {
                "image_slot": int(match.group(1)),
                "reported_version": match.group(3).strip(),
            }
            md5 = MD5_LINE_RE.search(text)
            if md5:
                image["reported_md5"] = md5.group(1).lower()
            images[Path(match.group(2)).name.lower()] = image
        dock = DOCK_DESCRIPTOR_RE.search(text)
        if dock:
            dock_versions[_descriptor_key(str(member.get("path") or ""))] = [int(dock.group(i)) for i in range(1, 4)]
    return images, dock_versions


def iter_auxiliary_payloads(analysis: dict[str, Any], prefix: str = "") -> Iterable[dict[str, Any]]:
    """Flatten leaf files from an analyzed aux-board tar, preserving nested paths."""
    members = analysis.get("members") or []
    images, dock_versions = _node_metadata(members)
    for member in members:
        member_path = str(member.get("path") or "")
        path = f"{prefix}!/{member_path}" if prefix else member_path
        nested = member.get("nested")
        if isinstance(nested, dict):
            yield from iter_auxiliary_payloads(nested, path)
            continue
        if member.get("type") != "file" or not member.get("sha256"):
            continue
        item = {
            "path": path,
            "filename": Path(member_path).name,
            "kind": member.get("kind") or "file",
            "role": _payload_role(path),
            "size": int(member.get("size") or 0),
            "sha256": str(member["sha256"]),
        }
        image_meta = images.get(Path(member_path).name.lower())
        if image_meta:
            item.update(image_meta)
        dock_version = dock_versions.get(_descriptor_key(member_path))
        if dock_version and item["kind"] in ("encrypted-firmware", "firmware-image"):
            item["descriptor_version_components"] = dock_version
            item["descriptor_version"] = ".".join(str(x) for x in dock_version)
        if isinstance(member.get("text"), str):
            item["text"] = member["text"]
        yield item


def iter_auxiliary_bundle_entries(value: Any) -> Iterable[dict[str, Any]]:
    """Yield hashed aux-board firmware bundle files from an analysis manifest."""
    if isinstance(value, dict):
        path = value.get("path")
        if (
            isinstance(path, str)
            and AUXILIARY_BUNDLE_MARKER in path
            and value.get("type") == "file"
            and value.get("sha256")
        ):
            yield value
        for child in value.values():
            yield from iter_auxiliary_bundle_entries(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_auxiliary_bundle_entries(child)


def build_auxiliary_index(catalog: dict[str, Any], data_root: Path) -> dict[str, Any]:
    """Build an index of firmware bundles preserved inside archived robot OTAs.

    Deep package analysis hashes regular files extracted from SquashFS/CPIO
    filesystems.  This turns the aux-board bundles that ship inside robot OTA
    packages into first-class, provenance-linked firmware evidence without
    duplicating their already-preserved bytes into Git history.
    """
    bundles: list[dict[str, Any]] = []
    seen_preserved_file: set[tuple[str, str, str]] = set()
    for record in catalog.get("firmwares") or []:
        archive = record.get("archive") or {}
        manifest_rel = archive.get("manifest")
        if not manifest_rel:
            continue
        manifest_path = data_root / str(manifest_rel)
        if not manifest_path.is_file():
            continue
        manifest = load_json(manifest_path, {})
        seen: set[tuple[str, str]] = set()
        for entry in iter_auxiliary_bundle_entries(manifest):
            path = str(entry["path"])
            sha256 = str(entry["sha256"])
            identity = (path, sha256)
            if identity in seen:
                continue
            seen.add(identity)
            preserved_identity = (str(manifest_rel), path, sha256)
            # A single physical parent package can have multiple catalog records
            # when it was recovered through both Content API and direct-CDN URLs.
            # Index the embedded bytes once per parent manifest.
            if preserved_identity in seen_preserved_file:
                continue
            seen_preserved_file.add(preserved_identity)
            analysis = entry.get("auxiliary_firmware") if isinstance(entry.get("auxiliary_firmware"), dict) else None
            payloads = list(iter_auxiliary_payloads(analysis)) if analysis else []
            bundles.append({
                "family": str(record.get("family") or ""),
                "parent_version": str(record.get("version") or ""),
                "path": path,
                "filename": Path(path).name,
                "sha256": sha256,
                "size": int(entry.get("size") or 0),
                "parent_firmware_sha256": archive.get("sha256"),
                "parent_release_tag": archive.get("release_tag"),
                "parent_asset_url": archive.get("asset_url"),
                "source_manifest": str(manifest_rel),
                "preservation": "embedded-in-archived-parent-firmware",
                "nested_analysis_available": analysis is not None,
                "payloads": payloads,
            })

    bundles.sort(key=lambda x: (x["family"], x["parent_version"], x["filename"], x["sha256"]))
    families = Counter(x["family"] for x in bundles)
    all_payloads = [payload for bundle in bundles for payload in bundle.get("payloads") or []]
    firmware_payloads = [x for x in all_payloads if x.get("kind") in ("encrypted-firmware", "firmware-image")]
    return {
        "schema": 1,
        "source": "deep filesystem analysis of archived iRobot robot firmware",
        "catalog_updated_at": catalog.get("updated_at"),
        "summary": {
            "bundle_count": len(bundles),
            "unique_sha256_count": len({x["sha256"] for x in bundles}),
            "parent_firmware_count": len({(x["family"], x["parent_version"], x["source_manifest"]) for x in bundles}),
            "nested_analyzed_bundle_count": sum(bool(x.get("nested_analysis_available")) for x in bundles),
            "payload_count": len(all_payloads),
            "unique_payload_sha256_count": len({x["sha256"] for x in all_payloads}),
            "firmware_payload_count": len(firmware_payloads),
            "unique_firmware_payload_sha256_count": len({x["sha256"] for x in firmware_payloads}),
            "families": dict(sorted(families.items())),
        },
        "bundles": bundles,
    }
