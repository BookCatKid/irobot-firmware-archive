from __future__ import annotations

import urllib.parse
from typing import Any


def _asset_name(url: str) -> str:
    return urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])


def audit_release_assets(catalog: dict[str, Any], releases: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare cataloged archive bytes with GitHub Release asset metadata.

    GitHub exposes a SHA-256 ``digest`` for Release assets.  Requiring both the
    expected byte length and digest catches accidental overwrites such as a
    same-name metapackage clobbering the much larger firmware payload.
    """
    by_tag = {str(release.get("tag_name")): release for release in releases}
    issues: list[dict[str, Any]] = []
    firmware_checked = 0
    metapackages_checked = 0
    seen_metapackages: set[tuple[str, str, str]] = set()

    def check_asset(*, tag: str, url: str, size: Any, sha256: Any, kind: str, identity: str) -> None:
        nonlocal firmware_checked, metapackages_checked
        release = by_tag.get(tag)
        if not release:
            issues.append({"kind": kind, "identity": identity, "issue": "release-missing", "release_tag": tag})
            return
        name = _asset_name(url)
        asset = next((x for x in release.get("assets") or [] if x.get("name") == name), None)
        if not asset:
            issues.append({"kind": kind, "identity": identity, "issue": "asset-missing", "release_tag": tag, "asset": name})
            return
        if kind == "firmware":
            firmware_checked += 1
        else:
            metapackages_checked += 1
        if int(asset.get("size") or -1) != int(size or -2):
            issues.append({
                "kind": kind, "identity": identity, "issue": "size-mismatch", "release_tag": tag,
                "asset": name, "expected": size, "actual": asset.get("size"),
            })
        expected_digest = f"sha256:{str(sha256).lower()}" if sha256 else None
        actual_digest = str(asset.get("digest") or "").lower()
        if not expected_digest:
            issues.append({"kind": kind, "identity": identity, "issue": "catalog-sha256-missing", "release_tag": tag, "asset": name})
        elif not actual_digest:
            issues.append({"kind": kind, "identity": identity, "issue": "release-digest-missing", "release_tag": tag, "asset": name})
        elif actual_digest != expected_digest:
            issues.append({
                "kind": kind, "identity": identity, "issue": "digest-mismatch", "release_tag": tag,
                "asset": name, "expected": expected_digest, "actual": actual_digest,
            })

    for record in catalog.get("firmwares") or []:
        archive = record.get("archive") or {}
        identity = f"{record.get('family')} {record.get('version')}"
        if not archive:
            continue
        tag = str(archive.get("release_tag") or "")
        url = str(archive.get("asset_url") or "")
        if not tag or not url or archive.get("size") is None or not archive.get("sha256"):
            issues.append({"kind": "firmware", "identity": identity, "issue": "archive-metadata-incomplete"})
            continue
        check_asset(
            tag=tag, url=url, size=archive.get("size"), sha256=archive.get("sha256"),
            kind="firmware", identity=identity,
        )

        meta = archive.get("metapackage") or {}
        if not meta or meta.get("same_as_firmware") is True or not meta.get("asset_url"):
            continue
        meta_key = (tag, str(meta.get("asset_url")), str(meta.get("sha256")))
        if meta_key in seen_metapackages:
            continue
        seen_metapackages.add(meta_key)
        check_asset(
            tag=tag, url=str(meta["asset_url"]), size=meta.get("size"), sha256=meta.get("sha256"),
            kind="metapackage", identity=identity,
        )

    return {
        "firmware_checked": firmware_checked,
        "metapackages_checked": metapackages_checked,
        "issue_count": len(issues),
        "issues": issues,
    }
