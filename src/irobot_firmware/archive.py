from __future__ import annotations

import subprocess
import urllib.parse
from pathlib import Path
from typing import Any

from .analyze import analyze
from .download import download
from .util import slug
from .release_notes import render_release_notes


def release_tag(record: dict[str, Any], sha256: str) -> str:
    return f"firmware-{slug(record['family'])}-{slug(record['version'])}-{sha256[:12]}"


def archive_one(
    record: dict[str, Any],
    repo: str,
    data_root: Path,
    work_root: Path,
    upload_release: bool = True,
    deep: bool = True,
) -> dict[str, Any]:
    family = slug(record["family"])
    version = slug(record["version"])
    url_name = Path(urllib.parse.urlsplit(record["url"]).path).name or f"{family}-{version}.signed"
    work = work_root / f"{family}-{version}"
    work.mkdir(parents=True, exist_ok=True)
    blob = work / url_name
    dl = download(record["url"], blob, record.get("size"))
    sha = str(dl["sha256"])
    manifest_rel = Path("firmware") / family / f"{version}-{sha[:12]}.json"
    manifest_path = data_root / manifest_rel
    analysis = analyze(blob, manifest_path, work / "analysis", deep=deep)
    tag = release_tag(record, sha)
    archive_url = None
    if upload_release:
        title = f"{record['family']} {record['version']} · iRobot firmware"
        notes = render_release_notes(record, analysis, sha, int(dl["size"]), data_root)
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
        "size": dl["size"],
        "release_tag": tag if upload_release else None,
        "asset_url": archive_url,
        "manifest": manifest_rel.as_posix(),
        "format": analysis.get("format"),
        "component_count": len(analysis.get("components", [])),
    }
