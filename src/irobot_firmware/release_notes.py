from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .util import load_json


def platform_metadata(record: dict[str, Any], data_root: Path) -> dict[str, Any]:
    cfg = load_json(data_root.parent / "config" / "platforms.json", {})
    return (cfg.get("platforms") or {}).get(str(record.get("family")), {})


def _value(v: Any) -> str:
    if v is None or v == "":
        return "—"
    return str(v)


def _code(v: Any) -> str:
    if v is None or v == "":
        return "—"
    return f"`{str(v)}`"


def _link(label: str, url: Any) -> str:
    if not url:
        return "—"
    return f"[{label}]({url})"


def render_release_notes(record: dict[str, Any], analysis: dict[str, Any], sha256: str, size: int, data_root: Path) -> str:
    platform = platform_metadata(record, data_root)
    models = platform.get("models") or []
    skus = sorted(set((platform.get("known_skus") or []) + ([record["source_sku"]] if record.get("source_sku") else [])))
    origin_blurb = (
        "This release preserves an **unmodified iRobot firmware payload embedded in an official iRobot app**."
        if record.get("source") == "app-embedded"
        else "This release preserves an **unmodified iRobot OTA package** exactly as it was retrieved from iRobot infrastructure."
    )
    source_heading = "Original app source" if record.get("source") == "app-embedded" else "Original OTA source"
    source_link_label = "source app" if record.get("source") == "app-embedded" else "original iRobot package"
    reported = analysis.get("reported_identity") or {}
    lines = [
        origin_blurb,
        "",
        "## Identity",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Firmware platform | {_code(record.get('family'))} |",
        f"| Platform type | {_value(platform.get('type'))} |",
        f"| Platform mapping confidence | {_code(platform.get('confidence'))} |",
        f"| Associated retail models | {_value(', '.join(models))} |",
        f"| Known / observed SKUs | {_value(', '.join(skus))} |",
        f"| Firmware version | {_code(record.get('version'))} |",
        f"| Package-reported version | {_code(reported.get('version'))} |",
        f"| Package-reported product version | {_code(reported.get('product_version'))} |",
        f"| Package-reported model | {_code(reported.get('model'))} |",
        f"| Release date | {_value(record.get('release_date'))} |",
        f"| Track | {_code(record.get('track'))} |",
        f"| Signing channel | {_code(record.get('signing'))} |",
        f"| Fused value | {_code(record.get('fused'))} |",
        "",
    ]
    if platform.get("description"):
        lines += [f"> {platform['description']}", ""]

    lines += [
        f"## {source_heading}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Package / source URL | {_link(source_link_label, record.get('url'))} |",
        f"| Source app package | {_code(record.get('source_package'))} |",
        f"| Source app version | {_code(record.get('source_app_version'))} |",
        f"| Embedded resource | {_code(record.get('source_resource'))} |",
        f"| Metapackage URL | {_link('iRobot metapackage', record.get('metapackage_url'))} |",
        f"| Deployment package | {_code(record.get('deployment_mpkg'))} |",
        f"| Discovery method | {_code(record.get('source'))} |",
        f"| Discovery SKU | {_code(record.get('source_sku'))} |",
        f"| Discovery software version | {_code(record.get('source_software_ver'))} |",
        f"| Release notes candidate | {_code(record.get('release_notes_version'))} |",
        f"| Release notes source | {_link('iRobot support article', record.get('release_notes_url'))} |",
        f"| Source ETag | {_code(record.get('etag'))} |",
        f"| Source Last-Modified | {_value(record.get('last_modified'))} |",
        f"| First discovered by archive | {_value(record.get('discovered_at'))} |",
        "",
    ]

    meta_archive = (record.get("archive") or {}).get("metapackage") or {}
    if meta_archive:
        embedded = meta_archive.get("embedded_urls") or []
        lines += [
            "## Signed metapackage",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Archived asset | {_link('download metapackage', meta_archive.get('asset_url'))} |",
            f"| Filename | {_code(meta_archive.get('filename'))} |",
            f"| Size | **{int(meta_archive.get('size') or 0):,} bytes** |",
            f"| SHA-256 | {_code(meta_archive.get('sha256'))} |",
            f"| Parsed format | {_code(meta_archive.get('format'))} |",
            f"| Analysis manifest | {_link('download manifest', meta_archive.get('manifest_asset_url'))} |",
            "",
        ]
        if embedded:
            lines += ["Embedded absolute URLs:", ""]
            lines += [f"- `{url}`" for url in embedded]
            lines.append("")

    lines += [
        "## Archived file",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Filename | {_code(analysis.get('filename'))} |",
        f"| Size | **{size:,} bytes** |",
        f"| SHA-256 | `{sha256}` |",
        f"| Parsed format | {_code(analysis.get('format'))} |",
        f"| Top-level components | **{len(analysis.get('components') or [])}** |",
        "",
    ]

    components = analysis.get("components") or []
    if components:
        lines += [
            "## Signed OTA components",
            "",
            "| Component | Kind | Size | SHA-256 | Metadata hash |",
            "| --- | --- | ---: | --- | --- |",
        ]
        for c in components:
            verified = c.get("metadata_hash_verified")
            verify_text = "verified" if verified is True else "mismatch" if verified is False else "not present"
            lines.append(
                f"| {_code(c.get('name'))} | {_code(c.get('kind'))} | {int(c.get('size') or 0):,} | "
                f"`{str(c.get('sha256') or '')}` | {verify_text} |"
            )
        lines.append("")

    fs_components = [c for c in components if c.get("filesystem_analysis")]
    if fs_components:
        lines += ["## Filesystem analysis", ""]
        for c in fs_components:
            fs = c.get("filesystem_analysis") or {}
            lines += [
                f"### {c.get('name', 'filesystem')}",
                "",
                f"- Filesystem: {_code(fs.get('filesystem'))}",
                f"- Extractable: **{bool(fs.get('extractable'))}**",
                f"- Regular files: **{int(fs.get('file_count') or 0):,}**",
                f"- Manifest entries: **{int(fs.get('entry_count') or 0):,}**",
            ]
            snapshots = fs.get("text_snapshots") or {}
            for key in ("opt/irobot/identity.env", "opt/irobot/version.env", "etc/os-release"):
                if snapshots.get(key):
                    lines += ["", f"**`/{key}`**", "", "```text", snapshots[key].rstrip(), "```"]
            lines.append("")

    cpio = analysis.get("cpio") or {}
    if cpio:
        lines += [
            "## SWUpdate / CPIO contents",
            "",
            f"- CPIO variant: {_code(cpio.get('variant'))}",
            f"- Entries: **{int(cpio.get('entry_count') or 0):,}**",
            f"- Trailer found: **{bool(cpio.get('trailer_found'))}**",
            "",
            "| Path | Type | Size | SHA-256 |",
            "| --- | --- | ---: | --- |",
        ]
        for entry in cpio.get("entries") or []:
            lines.append(
                f"| `{entry.get('path', '')}` | {_code(entry.get('type'))} | {int(entry.get('size') or 0):,} | "
                f"`{str(entry.get('sha256') or '')}` |"
            )
        lines.append("")
        snapshots = cpio.get("text_snapshots") or {}
        if snapshots.get("sw-description"):
            lines += ["**`sw-description`**", "", "```text", snapshots["sw-description"].rstrip(), "```", ""]
        for embedded_fs in cpio.get("embedded_filesystems") or []:
            fs = embedded_fs.get("analysis") or {}
            lines += [
                f"### Embedded filesystem: `{embedded_fs.get('path', '')}`",
                "",
                f"- Filesystem: {_code(fs.get('filesystem'))}",
                f"- Extractable: **{bool(fs.get('extractable'))}**",
                f"- Regular files: **{int(fs.get('file_count') or 0):,}**",
                f"- Manifest entries: **{int(fs.get('entry_count') or 0):,}**",
                "",
            ]

    evidence = platform.get("evidence") or []
    if evidence:
        lines += ["## Platform ↔ hardware evidence", ""]
        for item in evidence:
            detail = ", ".join(
                f"{k}={v}" for k, v in item.items() if k not in {"url", "kind"} and v not in (None, "")
            )
            suffix = f" — [source]({item['url']})" if item.get("url") else ""
            lines.append(f"- **{item.get('kind', 'evidence')}**: {detail}{suffix}")
        lines.append("")

    raw = {k: v for k, v in record.items() if k != "archive"}
    lines += [
        "## Raw discovery metadata",
        "",
        "```json",
        json.dumps(raw, indent=2, sort_keys=True),
        "```",
        "",
        "---",
        "Archived by [BookCatKid/irobot-firmware-archive](https://github.com/BookCatKid/irobot-firmware-archive). This is an unofficial community archive.",
    ]
    return "\n".join(lines) + "\n"
