from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .util import load_json


AUXILIARY_BUNDLE_MARKER = "auxboard_firmware"


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
            })

    bundles.sort(key=lambda x: (x["family"], x["parent_version"], x["filename"], x["sha256"]))
    families = Counter(x["family"] for x in bundles)
    return {
        "schema": 1,
        "source": "deep filesystem analysis of archived iRobot robot firmware",
        "catalog_updated_at": catalog.get("updated_at"),
        "summary": {
            "bundle_count": len(bundles),
            "unique_sha256_count": len({x["sha256"] for x in bundles}),
            "parent_firmware_count": len({(x["family"], x["parent_version"], x["source_manifest"]) for x in bundles}),
            "families": dict(sorted(families.items())),
        },
        "bundles": bundles,
    }
