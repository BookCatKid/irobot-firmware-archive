from __future__ import annotations

import html
import concurrent.futures
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .util import load_json

CONTENT_API = "https://content-prod.iot.irobotapi.com/v2/firmware"
DEFAULT_UA = "irobot-firmware-archive/0.1 (+https://github.com/BookCatKid/irobot-firmware-archive)"


def _request_json(url: str, timeout: int = 20) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _exists(url: str, timeout: int = 20) -> tuple[bool, dict[str, str]]:
    # iRobot/S3 endpoints reliably support a 1-byte Range GET even when HEAD semantics vary.
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA, "Range": "bytes=0-0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status in (200, 206), headers
    except urllib.error.HTTPError as exc:
        return False, {k.lower(): v for k, v in exc.headers.items()}


def api_probe(sku: str, software_ver: str, track: str = "prod") -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({"sku": sku, "softwareVer": software_ver, "track": track})
    data = _request_json(f"{CONTENT_API}?{query}")
    now = datetime.now(timezone.utc).isoformat()
    result = []
    for item in data.get("firmware", []):
        url = item.get("downloadUrl") or item.get("metapackageUrl")
        if not url:
            continue
        deployment = item.get("deploymentMpkg") or ""
        family = deployment.split("/", 1)[0] if "/" in deployment else _family_from_url(url)
        result.append({
            "family": family or "unknown",
            "version": str(item.get("version") or "unknown"),
            "url": url,
            "metapackage_url": item.get("metapackageUrl"),
            "source": "content-api",
            "source_sku": sku,
            "source_software_ver": software_ver,
            "track": item.get("track", track),
            "release_date": item.get("releaseDate"),
            "signing": item.get("signing"),
            "fused": item.get("fused"),
            "deployment_mpkg": item.get("deploymentMpkg"),
            "discovered_at": now,
        })
    return result


def _family_from_url(url: str) -> str:
    name = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]
    for suffix in ("-prod.meta.signed", ".signed"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    parts = name.split("-")
    return parts[0] if parts else "unknown"


def direct_probe(family: str, version: str, template: str) -> dict[str, Any] | None:
    url = template.format(family=family, version=version)
    exists, headers = _exists(url)
    if not exists:
        return None
    total = None
    content_range = headers.get("content-range", "")
    if "/" in content_range:
        try:
            total = int(content_range.rsplit("/", 1)[1])
        except ValueError:
            pass
    if total is None and headers.get("content-length"):
        try:
            total = int(headers["content-length"])
        except ValueError:
            pass
    return {
        "family": family,
        "version": version,
        "url": url,
        "source": "direct-probe",
        "track": "prod",
        "size": total,
        "etag": headers.get("etag", "").strip('"') or None,
        "last_modified": headers.get("last-modified"),
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }



def release_note_versions(url: str, timeout: int = 20) -> list[str]:
    """Extract dotted firmware versions from iRobot's static support article HTML."""
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA, "Accept": "text/html"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
    text = html.unescape(re.sub(r"<[^>]+>", " ", body))
    text = re.sub(r"\s+", " ", text)
    # Release-note pages mix versions and dates. Limit segments to 1-2 digits so years like 2025
    # are excluded, then require a nearby 'Version' token where possible.
    found: set[str] = set()
    for match in re.finditer(r"\bVersion\s+([0-9]{1,2}(?:\.[0-9]{1,2}){1,3})\b", text, re.I):
        found.add(match.group(1))
    # Some headings contain forms such as '24.29.02/24.29.03'. Capture those too.
    for match in re.finditer(r"\b([0-9]{1,2}(?:\.[0-9]{1,2}){2})\b", text):
        v = match.group(1)
        if int(v.split(".", 1)[0]) <= 30:
            found.add(v)
    return sorted(found)


def version_filename_candidates(version: str) -> list[str]:
    parts = version.split(".")
    candidates = {version}
    if len(parts) >= 3 and all(p.isdigit() for p in parts):
        candidates.add(".".join([parts[0], parts[1], parts[2].zfill(2), *parts[3:]]))
        candidates.add(".".join([parts[0], parts[1].zfill(2), parts[2].zfill(2), *parts[3:]]))
    return sorted(candidates)

def discover_from_config(config_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    cfg = load_json(config_path, {})
    records: list[dict[str, Any]] = []
    errors: list[str] = []

    for probe in cfg.get("api_probes", []):
        for software_ver in probe.get("software_versions", ["0.0.0"]):
            try:
                records.extend(api_probe(probe["sku"], software_ver, probe.get("track", "prod")))
            except Exception as exc:  # Discovery is best-effort; one family should not stop the rest.
                errors.append(f"api {probe.get('sku')} {software_ver}: {exc}")

    for family in cfg.get("direct_families", []):
        template = family["template"]
        for version in family.get("versions", []):
            try:
                hit = direct_probe(family["family"], version, template)
                if hit:
                    records.append(hit)
            except Exception as exc:
                errors.append(f"direct {family.get('family')} {version}: {exc}")

    # Official release notes act as a low-cost candidate-version feed. This matters for families
    # such as sapphire where the content API may return an empty eligibility list even though
    # a newer firmware version exists publicly.
    for notes in cfg.get("release_note_probes", []):
        try:
            versions = release_note_versions(notes["url"])
        except Exception as exc:
            errors.append(f"release notes {notes.get('url')}: {exc}")
            continue
        # Some newer products do not expose a guessable direct-object filename.  The app
        # contains default SKUs for those product families, so feed every version mentioned
        # in the corresponding official release notes back through the content API.  The API
        # can return different target packages depending on the supplied current version.
        api_tasks = []
        for sku in notes.get("api_skus", []):
            for release_version in versions:
                for candidate in version_filename_candidates(release_version):
                    api_tasks.append((sku, release_version, candidate))
        if api_tasks:
            def _notes_api_task(task):
                sku, release_version, candidate = task
                return task, api_probe(sku, candidate, notes.get("track", "prod"))
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(api_tasks))) as pool:
                futures = {pool.submit(_notes_api_task, task): task for task in api_tasks}
                for future in concurrent.futures.as_completed(futures):
                    sku, release_version, candidate = futures[future]
                    try:
                        _, api_hits = future.result()
                        for hit in api_hits:
                            hit["source"] = "release-notes-api"
                            hit["release_notes_url"] = notes["url"]
                            hit["release_notes_version"] = release_version
                            hit["app_derived_sku"] = True
                            records.append(hit)
                    except Exception as exc:
                        errors.append(f"notes api {sku} {candidate}: {exc}")

        direct_tasks = []
        for family in notes.get("families", []):
            template = family["template"]
            for release_version in versions:
                for candidate in version_filename_candidates(release_version):
                    direct_tasks.append((family["family"], template, release_version, candidate))
        if direct_tasks:
            def _notes_direct_task(task):
                family_name, template, release_version, candidate = task
                return task, direct_probe(family_name, candidate, template)
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(direct_tasks))) as pool:
                futures = {pool.submit(_notes_direct_task, task): task for task in direct_tasks}
                for future in concurrent.futures.as_completed(futures):
                    family_name, template, release_version, candidate = futures[future]
                    try:
                        _, hit = future.result()
                        if hit:
                            hit["source"] = "release-notes-probe"
                            hit["release_notes_url"] = notes["url"]
                            hit["release_notes_version"] = release_version
                            records.append(hit)
                    except Exception as exc:
                        errors.append(f"notes direct {family_name} {candidate}: {exc}")

    # De-duplicate exact packages found through multiple probes while retaining the richer record.
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in records:
        key = (record["family"], record["version"], record["url"])
        if key not in merged or len(record) > len(merged[key]):
            merged[key] = record
    return list(merged.values()), errors
