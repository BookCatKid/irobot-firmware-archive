from __future__ import annotations

import subprocess
import urllib.parse
from pathlib import Path
from typing import Any

from .analyze import analyze
from .download import download
from .discover import extract_metapackage_urls, firmware_urls_from_metapackage_urls
from .util import sha256_file, slug
from .release_notes import render_release_notes


def release_tag(record: dict[str, Any], sha256: str) -> str:
    return f"firmware-{slug(record['family'])}-{slug(record['version'])}-{sha256[:12]}"


def archive_blob(
    record: dict[str, Any],
    blob: Path,
    repo: str,
    data_root: Path,
    work_root: Path,
    upload_release: bool = True,
    deep: bool = True,
    existing_by_sha: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    family = slug(record["family"])
    version = slug(record["version"])
    work = work_root / f"{family}-{version}"
    work.mkdir(parents=True, exist_ok=True)
    sha = sha256_file(blob)
    size = blob.stat().st_size
    manifest_rel = Path("firmware") / family / f"{version}-{sha[:12]}.json"
    manifest_path = data_root / manifest_rel
    analysis = analyze(blob, manifest_path, work / "analysis", deep=deep)
    tag = release_tag(record, sha)
    archive_url = None
    existing = (existing_by_sha or {}).get(sha)
    if existing:
        return {
            "sha256": sha,
            "size": size,
            "release_tag": existing.get("release_tag"),
            "asset_url": existing.get("asset_url"),
            "manifest": manifest_rel.as_posix(),
            "format": analysis.get("format"),
            "component_count": len(analysis.get("components", [])),
            "reported_identity": analysis.get("reported_identity"),
            "deduplicated": True,
        }
    if upload_release:
        title = f"{record['family']} {record['version']} · iRobot firmware"
        notes = render_release_notes(record, analysis, sha, size, data_root)
        release_notes_path = work / "RELEASE_NOTES.md"
        release_notes_path.write_text(notes)
        check = subprocess.run(["gh", "release", "view", tag, "--repo", repo], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check.returncode != 0:
            subprocess.run(["gh", "release", "create", tag, "--repo", repo, "--title", title, "--notes-file", str(release_notes_path)], check=True)
        else:
            subprocess.run(["gh", "release", "edit", tag, "--repo", repo, "--title", title, "--notes-file", str(release_notes_path)], check=True)
        subprocess.run(["gh", "release", "upload", tag, str(blob), str(manifest_path), "--repo", repo, "--clobber"], check=True)
        archive_url = f"https://github.com/{repo}/releases/download/{tag}/{urllib.parse.quote(blob.name)}"
    return {
        "sha256": sha,
        "size": size,
        "release_tag": tag if upload_release else None,
        "asset_url": archive_url,
        "manifest": manifest_rel.as_posix(),
        "format": analysis.get("format"),
        "component_count": len(analysis.get("components", [])),
        "reported_identity": analysis.get("reported_identity"),
    }


def archive_one(
    record: dict[str, Any],
    repo: str,
    data_root: Path,
    work_root: Path,
    upload_release: bool = True,
    deep: bool = True,
    existing_by_sha: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    family = slug(record["family"])
    version = slug(record["version"])
    url_name = Path(urllib.parse.urlsplit(record["url"]).path).name or f"{family}-{version}.signed"
    work = work_root / f"{family}-{version}"
    work.mkdir(parents=True, exist_ok=True)
    blob = work / url_name
    download(record["url"], blob, record.get("size"))
    archive_data = archive_blob(record, blob, repo, data_root, work_root, upload_release=upload_release, deep=deep, existing_by_sha=existing_by_sha)
    meta = archive_metapackage(record, archive_data, repo, data_root, work_root, upload_release=upload_release)
    if meta:
        archive_data["metapackage"] = meta
    return archive_data


def archive_metapackage(
    record: dict[str, Any],
    archive_data: dict[str, Any],
    repo: str,
    data_root: Path,
    work_root: Path,
    upload_release: bool = True,
) -> dict[str, Any] | None:
    """Preserve and fingerprint the signed metapackage associated with an OTA.

    The content API exposes metapackages separately from the large OTA package.
    Older/current metapackages can contain the canonical prod-ota-firmware URL,
    so preserving them is part of preserving the update provenance rather than
    just keeping the final payload.
    """
    url = record.get("metapackage_url")
    if not url:
        return None
    family = slug(record["family"])
    version = slug(record["version"])
    filename = Path(urllib.parse.urlsplit(str(url)).path).name or f"{family}-{version}-metapackage.signed"
    work = work_root / f"{family}-{version}" / "metapackage"
    work.mkdir(parents=True, exist_ok=True)
    blob = work / filename
    dl = download(str(url), blob)
    sha = str(dl["sha256"])
    size = int(dl["size"])
    same_as_firmware = bool(archive_data.get("sha256")) and sha == archive_data.get("sha256")
    tag = archive_data.get("release_tag")
    base = f"https://github.com/{repo}/releases/download/{tag}/" if tag else None

    if same_as_firmware:
        # Several legacy V1 responses call a URL a metapackage even though that
        # endpoint serves byte-for-byte the same full firmware payload. Preserve
        # the endpoint as provenance, but do not create a second analysis artifact
        # or mine random URL strings from the firmware body as metapackage fields.
        firmware_manifest = archive_data.get("manifest")
        return {
            "role": "legacy-metapackage-endpoint-alias",
            "same_as_firmware": True,
            "url": str(url),
            "filename": blob.name,
            "sha256": sha,
            "size": size,
            "asset_url": archive_data.get("asset_url"),
            "manifest": firmware_manifest,
            "manifest_asset_url": (
                base + urllib.parse.quote(Path(str(firmware_manifest)).name)
                if base and firmware_manifest else None
            ),
            "format": archive_data.get("format"),
            "embedded_urls": [],
            "firmware_urls": [],
        }

    manifest_rel = Path("metapackages") / family / f"{version}-{sha[:12]}.json"
    manifest_path = data_root / manifest_rel
    analysis = analyze(blob, manifest_path, work / "analysis", deep=False)
    embedded_urls = extract_metapackage_urls(blob.read_bytes())
    firmware_urls = firmware_urls_from_metapackage_urls(embedded_urls)
    asset_url = None
    manifest_asset_url = None
    if upload_release and tag:
        subprocess.run(
            ["gh", "release", "upload", str(tag), str(blob), str(manifest_path), "--repo", repo, "--clobber"],
            check=True,
        )
        asset_url = base + urllib.parse.quote(blob.name)
        manifest_asset_url = base + urllib.parse.quote(manifest_path.name)
    return {
        "role": "signed-metapackage",
        "same_as_firmware": False,
        "url": str(url),
        "filename": blob.name,
        "sha256": sha,
        "size": size,
        "asset_url": asset_url,
        "manifest": manifest_rel.as_posix(),
        "manifest_asset_url": manifest_asset_url,
        "format": analysis.get("format"),
        "embedded_urls": embedded_urls,
        "firmware_urls": firmware_urls,
    }


def refresh_release_notes(
    record: dict[str, Any],
    repo: str,
    data_root: Path,
    work_root: Path,
) -> None:
    """Refresh a non-deduplicated release after auxiliary artifacts are added."""
    archive_data = record.get("archive") or {}
    tag = archive_data.get("release_tag")
    manifest_rel = archive_data.get("manifest")
    if not tag or not manifest_rel or archive_data.get("deduplicated"):
        return
    manifest_path = data_root / str(manifest_rel)
    if not manifest_path.is_file():
        return
    import json
    analysis = json.loads(manifest_path.read_text())
    notes = render_release_notes(record, analysis, str(archive_data.get("sha256") or ""), int(archive_data.get("size") or 0), data_root)
    work = work_root / f"{slug(record['family'])}-{slug(record['version'])}"
    work.mkdir(parents=True, exist_ok=True)
    notes_path = work / "RELEASE_NOTES.md"
    notes_path.write_text(notes)
    subprocess.run(
        ["gh", "release", "edit", str(tag), "--repo", repo, "--title", f"{record['family']} {record['version']} · iRobot firmware", "--notes-file", str(notes_path)],
        check=True,
    )
