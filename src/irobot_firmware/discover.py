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
LEGACY_CONTENT_V1 = "https://content-prod.iot.irobotapi.com/v1/app/"
DEFAULT_UA = "irobot-firmware-archive/0.1 (+https://github.com/BookCatKid/irobot-firmware-archive)"


def _request_json(url: str, timeout: int = 20) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_metapackage_urls(body: bytes) -> list[str]:
    """Extract unique absolute URLs from a signed iRobot metapackage body.

    Older aPKG metapackages carry the canonical OTA URL as a NUL-terminated
    string.  We intentionally do not guess undocumented aPKG field offsets:
    an absolute URL is self-describing evidence and is safe to preserve as
    provenance.
    """
    urls = [
        m.group().decode("ascii")
        for m in re.finditer(rb"https?://[^\x00\s\"<>]{5,500}", body)
    ]
    return list(dict.fromkeys(urls))


def metapackage_embedded_urls(url: str, timeout: int = 20) -> list[str]:
    """Fetch a small signed iRobot metapackage and return embedded URLs."""
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(1024 * 1024 + 1)
    if len(body) > 1024 * 1024:
        # True metapackages observed in production are tiny. Some legacy V1
        # responses expose the full firmware again under a /metapackage/ path;
        # do not mine arbitrary firmware strings as though they were metapackage
        # header fields.
        return []
    return extract_metapackage_urls(body)


def firmware_urls_from_metapackage_urls(urls: Iterable[str]) -> list[str]:
    """Keep only self-describing iRobot firmware-object URLs from metapackage strings."""
    result: list[str] = []
    for url in urls:
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        if not host.endswith("irobotapi.com"):
            continue
        if not path.endswith((".signed", ".prodsigned", ".enc")):
            continue
        result.append(url)
    return list(dict.fromkeys(result))


def _exists(url: str, timeout: int = 20) -> tuple[bool, dict[str, str]]:
    # iRobot/S3 endpoints reliably support a 1-byte Range GET even when HEAD semantics vary.
    # Some legacy CloudFront/S3 paths return HTTP 200 with a tiny XML NoSuchKey body,
    # so status alone is not sufficient evidence that a firmware object exists.
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA, "Range": "bytes=0-0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            content_type = headers.get("content-type", "").lower()
            if "xml" in content_type:
                return False, headers
            body = resp.read(1024)
            stripped = body.lstrip()
            if stripped.startswith(b"<?xml") and b"<Error>" in stripped and any(
                marker in stripped for marker in (b"<Code>NoSuchKey</Code>", b"<Code>AccessDenied</Code>")
            ):
                return False, headers
            # A legacy CloudFront edge can range a cached 292-byte NoSuchKey XML as
            # a 1-byte binary response.  For genuinely tiny objects (metapackages
            # are ~2 KiB), fetch the full body once and reject explicit S3 errors.
            content_range = headers.get("content-range", "")
            total_size = None
            if "/" in content_range:
                try:
                    total_size = int(content_range.rsplit("/", 1)[1])
                except ValueError:
                    pass
            if total_size is not None and total_size <= 4096:
                verify_req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
                with urllib.request.urlopen(verify_req, timeout=timeout) as verify_resp:
                    verify_body = verify_resp.read(4097).lstrip()
                if verify_body.startswith(b"<?xml") and b"<Error>" in verify_body and any(
                    marker in verify_body for marker in (b"<Code>NoSuchKey</Code>", b"<Code>AccessDenied</Code>")
                ):
                    return False, headers
            return resp.status in (200, 206), headers
    except urllib.error.HTTPError as exc:
        return False, {k.lower(): v for k, v in exc.headers.items()}



def legacy_v1_response(sku: str) -> dict[str, Any]:
    """Return the Classic-app V1 firmware catalog for an evidence-backed SKU."""
    return _request_json(LEGACY_CONTENT_V1 + "firmware/" + urllib.parse.quote(sku, safe=""))


def _legacy_item_family(item: dict[str, Any]) -> str | None:
    deployment = str(item.get("deploymentMpkg") or "")
    filename = deployment.rsplit("/", 1)[-1].lower()
    for family in ("roomba9xx", "marconi", "ningbo", "aero", "daredevil", "elpaso", "lewis", "sanmarino", "soho", "wichita", "altadena"):
        if family in filename:
            return family
    prefix = deployment.split("/", 1)[0].lower() if "/" in deployment else ""
    aliases = {"r980r960": "roomba9xx", "i7": "lewis", "m6": "sanmarino", "s9": "soho", "t72": "wichita"}
    if prefix in aliases:
        return aliases[prefix]
    return prefix or None


def _legacy_dotted_version(value: Any) -> str | None:
    raw = str(value or "").lstrip("vV")
    match = re.match(r"(\d+\.\d+\.\d+(?:-\d+)?)", raw)
    return match.group(1) if match else None


def _legacy_identity_from_url(item: dict[str, Any], url: str) -> tuple[str | None, str | None]:
    name = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]
    lower = name.lower()
    match = re.fullmatch(r"(roomba9xx|marconi)v(\d+)\.signed", lower)
    if match:
        return match.group(1), "v" + match.group(2)
    if re.fullmatch(r"altadenad\d+\.enc", lower):
        return "altadena", _legacy_dotted_version(item.get("version")) or str(item.get("version") or "unknown")
    match = re.fullmatch(r"([a-z][a-z0-9_-]*?)(\d+)\.signed", lower)
    if match:
        family = match.group(1).rstrip("-_v")
        expected = _legacy_item_family(item)
        if family == expected:
            return family, _legacy_dotted_version(item.get("version")) or ("v" + match.group(2))
        return family, "v" + match.group(2)
    return _legacy_item_family(item), _legacy_dotted_version(item.get("version"))


def _legacy_recovery_urls(item: dict[str, Any]) -> list[str]:
    """Generate evidence-backed legacy OTA candidates from V1 deployment metadata.

    The V1 API frequently keeps a stale but live ``downloadUrl`` (notably
    ``marconiv3210.signed``) after the deployment metadata has moved on.  The
    deploymentMpkg basename is stronger evidence for the intended artifact, so
    generate candidates from it first and only accept a candidate after a live
    range probe in ``legacy_v1_probe``.
    """
    family = _legacy_item_family(item)
    if not family:
        return []

    deployment = str(item.get("deploymentMpkg") or "")
    filename = deployment.rsplit("/", 1)[-1]
    stem = filename
    for suffix in (
        "-prod.meta.prodsigned", "-cn.meta.prodsigned",
        "-prod.meta.signed", "-cn.meta.signed",
        ".meta.prodsigned", ".meta.signed",
    ):
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break

    raw = str(item.get("version") or "").lstrip("vV")
    dotted = _legacy_dotted_version(raw)
    dotted_base = dotted.split("-", 1)[0] if dotted else ""
    compact = "".join(dotted_base.split(".")) if dotted_base else ""
    all_digits = re.sub(r"\D", "", raw)

    names: list[str] = []
    if stem and stem != filename and re.fullmatch(r"[A-Za-z0-9+_.-]+", stem):
        names.append(stem + ".signed")
    for token in dict.fromkeys((all_digits, compact)):
        if not token:
            continue
        names.extend((f"{family}v{token}.signed", f"{family}{token}.signed"))
    if dotted_base:
        names.append(f"{family}-{dotted_base}.signed")

    base = "https://prod-ota-firmware.iot.irobotapi.com/"
    return [base + name for name in dict.fromkeys(names)]


def _legacy_url_matches_deployment(item: dict[str, Any], url: str) -> bool:
    """Return whether a V1 URL basename is consistent with deployment metadata."""
    name = urllib.parse.urlsplit(str(url or "")).path.rsplit("/", 1)[-1].lower()
    if not name:
        return False
    deployment_name = str(item.get("deploymentMpkg") or "").rsplit("/", 1)[-1].lower()
    if name == deployment_name:
        return True
    candidate_names = {
        urllib.parse.urlsplit(candidate).path.rsplit("/", 1)[-1].lower()
        for candidate in _legacy_recovery_urls(item)
    }
    return name in candidate_names


def legacy_v1_probe(sku: str) -> list[dict[str, Any]]:
    """Recover downloadable firmware referenced by the Classic app's V1 catalog.

    The old endpoint often leaves historical rows in place after replacing their
    download URL with www.irobot.com/google.com.  For those rows we only accept a
    compact prod-ota-firmware candidate when a live range probe proves the object
    exists.  No placeholder is promoted to a firmware record on naming alone.
    """
    data = legacy_v1_response(sku)
    now = datetime.now(timezone.utc).isoformat()
    records: list[dict[str, Any]] = []
    for item in data.get("firmwareUpdateItems", []):
        original_url = str(item.get("downloadUrl") or "")
        chosen_url: str | None = None
        recovery_urls = _legacy_recovery_urls(item)
        # The deployment metadata is the historical selection record. Prefer a
        # live object reconstructed from it over a stale-but-live downloadUrl.
        for candidate in recovery_urls:
            try:
                if _exists(candidate)[0]:
                    chosen_url = candidate
                    break
            except Exception:
                continue
        # Only fall back to the V1 URL when its basename is structurally
        # consistent with the deployment metadata. Several V1 rows point at a
        # live marconiv3210.signed object while describing unrelated Lewis or
        # later Marconi deployments; status=200/206 alone is not identity proof.
        if chosen_url is None and "irobotapi.com" in original_url and _legacy_url_matches_deployment(item, original_url):
            try:
                if _exists(original_url)[0]:
                    chosen_url = original_url
            except Exception:
                pass
        if chosen_url is None:
            continue
        family, version = _legacy_identity_from_url(item, chosen_url)
        if not family or not version:
            continue
        # ContentStack sometimes mirrors the exact legacy artifact under a SKU path.
        # Prefer the canonical prod-ota-firmware object when the same basename is
        # independently live; this avoids duplicate catalog rows for byte aliases.
        filename = urllib.parse.urlsplit(chosen_url).path.rsplit("/", 1)[-1]
        if filename and (family in {"roomba9xx", "marconi"}):
            canonical = "https://prod-ota-firmware.iot.irobotapi.com/" + filename
            try:
                if _exists(canonical)[0]:
                    chosen_url = canonical
            except Exception:
                pass
        meta_original = str(item.get("metapackageUrl") or "")
        meta_url = None
        if "irobotapi.com" in meta_original and _legacy_url_matches_deployment(item, meta_original):
            try:
                if _exists(meta_original)[0]:
                    meta_url = meta_original
            except Exception:
                pass
        record: dict[str, Any] = {
            "family": family,
            "version": version,
            "url": chosen_url,
            "source": "legacy-v1-api",
            "source_sku": sku,
            "track": "prod",
            "release_date": item.get("releaseDate"),
            "deployment_mpkg": item.get("deploymentMpkg"),
            "legacy_v1_catalog_version": item.get("version"),
            "legacy_v1_original_download_url": item.get("downloadUrl"),
            "legacy_v1_original_metapackage_url": item.get("metapackageUrl"),
            "discovered_at": now,
        }
        if "irobotapi.com" in original_url and not _legacy_url_matches_deployment(item, original_url):
            record["legacy_v1_original_download_url_mismatch"] = True
        if "irobotapi.com" in meta_original and not _legacy_url_matches_deployment(item, meta_original):
            record["legacy_v1_original_metapackage_url_mismatch"] = True
        if item.get("notes") not in (None, "", " "):
            record["legacy_v1_notes"] = item.get("notes")
        if meta_url:
            record["metapackage_url"] = meta_url
        if chosen_url != original_url:
            record["legacy_v1_recovered_from_deployment_metadata"] = True
        records.append(record)
    return records


def api_probe_response(
    sku: str,
    software_ver: str,
    track: str | None = "prod",
    *,
    dock_fw_ver: str | None = None,
    dock_fw_ver_sec: str | None = None,
    dock_hw_rev: str | None = None,
) -> dict[str, Any]:
    """Return the raw v2 firmware response using the query shape from Roomba Home 3.1.0."""
    params: dict[str, str] = {"sku": sku, "softwareVer": software_ver}
    for key, value in (
        ("track", track),
        ("dockFwVer", dock_fw_ver),
        ("dockFwVerSec", dock_fw_ver_sec),
        ("dockHwRev", dock_hw_rev),
    ):
        if value is not None:
            params[key] = value
    return _request_json(f"{CONTENT_API}?{urllib.parse.urlencode(params)}")


def api_probe(
    sku: str,
    software_ver: str,
    track: str | None = "prod",
    *,
    dock_fw_ver: str | None = None,
    dock_fw_ver_sec: str | None = None,
    dock_hw_rev: str | None = None,
) -> list[dict[str, Any]]:
    data = api_probe_response(
        sku,
        software_ver,
        track,
        dock_fw_ver=dock_fw_ver,
        dock_fw_ver_sec=dock_fw_ver_sec,
        dock_hw_rev=dock_hw_rev,
    )
    now = datetime.now(timezone.utc).isoformat()
    result = []
    dock = data.get("dock")
    request_dock_state = {
        key: value
        for key, value in {
            "dockFwVer": dock_fw_ver,
            "dockFwVerSec": dock_fw_ver_sec,
            "dockHwRev": dock_hw_rev,
        }.items()
        if value is not None
    }
    for item in data.get("firmware", []):
        url = item.get("downloadUrl") or item.get("metapackageUrl")
        if not url:
            continue
        deployment = item.get("deploymentMpkg") or ""
        family = deployment.split("/", 1)[0] if "/" in deployment else _family_from_url(url)
        record = {
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
        }
        # Prime 3.1.0 also decodes a top-level `dock` recommendation. It is metadata
        # (version/priorities/track/install time), not a downloadable firmware package.
        if isinstance(dock, dict) and dock:
            record["dock_firmware_recommendation"] = dock
        if request_dock_state:
            record["source_dock_state"] = request_dock_state
        if record.get("metapackage_url"):
            try:
                aliases = metapackage_embedded_urls(str(record["metapackage_url"]))
            except Exception:
                aliases = []
            if aliases:
                record["metapackage_embedded_urls"] = aliases
        result.append(record)
    return result


def _family_from_url(url: str) -> str:
    name = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]
    for suffix in ("-prod.meta.signed", ".signed"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    parts = name.split("-")
    return parts[0] if parts else "unknown"


def direct_probe(family: str, version: str, template: str) -> dict[str, Any] | None:
    # Legacy iRobot firmware names use more than one version encoding.  Modern
    # packages generally preserve dots (``sapphire-24.29.03.signed``), while
    # older families such as Marconi embed a compact dotted release version
    # (``marconiv327.signed`` for 3.2.7).  Templates may opt into either form.
    parts = version.split(".")
    padded_compact = (
        "".join(part.zfill(2) for part in parts)
        if parts and all(part.isdigit() for part in parts)
        else version.replace(".", "")
    )
    url = template.format(
        family=family,
        version=version,
        compact=version.replace(".", ""),
        version_compact=version.replace(".", ""),
        padded_compact=padded_compact,
        version_padded_compact=padded_compact,
    )
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


def version_filename_candidates(version: str, patch_expansion_max: int | None = None) -> list[str]:
    parts = version.split(".")
    candidates = {version}
    if len(parts) >= 3 and all(p.isdigit() for p in parts):
        candidates.add(".".join([parts[0], parts[1], parts[2].zfill(2), *parts[3:]]))
        candidates.add(".".join([parts[0], parts[1].zfill(2), parts[2].zfill(2), *parts[3:]]))
    elif len(parts) == 2 and all(p.isdigit() for p in parts) and patch_expansion_max is not None:
        for patch in range(max(0, patch_expansion_max) + 1):
            candidates.add(f"{parts[0]}.{parts[1]}.{patch}")
            candidates.add(f"{parts[0]}.{parts[1]}.{patch:02d}")
    return sorted(candidates)

def discover_from_config(config_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    cfg = load_json(config_path, {})
    records: list[dict[str, Any]] = []
    errors: list[str] = []

    legacy_skus = [str(sku) for sku in cfg.get("legacy_v1_skus", [])]
    if legacy_skus:
        # Each SKU is independent network I/O. Run them concurrently but append
        # results back in config order so catalog provenance remains deterministic.
        legacy_results: dict[str, list[dict[str, Any]]] = {}
        legacy_errors: dict[str, Exception] = {}
        workers = max(1, min(int(cfg.get("legacy_v1_workers", 12)), len(legacy_skus)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(legacy_v1_probe, sku): sku for sku in legacy_skus}
            for future in concurrent.futures.as_completed(futures):
                sku = futures[future]
                try:
                    legacy_results[sku] = future.result()
                except Exception as exc:
                    legacy_errors[sku] = exc
        for sku in legacy_skus:
            records.extend(legacy_results.get(sku, []))
            if sku in legacy_errors:
                errors.append(f"legacy-v1 {sku}: {legacy_errors[sku]}")

    for probe in cfg.get("api_probes", []):
        for software_ver in probe.get("software_versions", ["0.0.0"]):
            try:
                records.extend(api_probe(
                    probe["sku"],
                    software_ver,
                    probe.get("track", "prod"),
                    dock_fw_ver=probe.get("dockFwVer"),
                    dock_fw_ver_sec=probe.get("dockFwVerSec"),
                    dock_hw_rev=probe.get("dockHwRev"),
                ))
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
                for candidate in version_filename_candidates(release_version, notes.get("patch_expansion_max")):
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
                for candidate in version_filename_candidates(release_version, notes.get("patch_expansion_max")):
                    direct_tasks.append((family["family"], template, release_version, candidate, family.get("catalog_version")))
        if direct_tasks:
            def _notes_direct_task(task):
                family_name, template, release_version, candidate, catalog_version = task
                return task, direct_probe(family_name, candidate, template)
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(direct_tasks))) as pool:
                futures = {pool.submit(_notes_direct_task, task): task for task in direct_tasks}
                for future in concurrent.futures.as_completed(futures):
                    family_name, template, release_version, candidate, catalog_version = futures[future]
                    try:
                        _, hit = future.result()
                        if hit:
                            hit["source"] = "release-notes-probe"
                            hit["release_notes_url"] = notes["url"]
                            hit["release_notes_version"] = release_version
                            if catalog_version == "vcompact":
                                token = release_version.replace(".", "")
                                hit["filename_token"] = f"v{token}"
                                hit["version"] = f"v{token}"
                            records.append(hit)
                    except Exception as exc:
                        errors.append(f"notes direct {family_name} {candidate}: {exc}")

    # De-duplicate exact packages found through multiple probes while retaining the richer record.
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in records:
        key = (record["family"], record["version"], record["url"])
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(record)
            existing = merged[key]
        else:
            first_source_sku = existing.get("source_sku")
            if len(record) > len(existing):
                replacement = dict(record)
                if first_source_sku:
                    replacement["source_sku"] = first_source_sku
                merged[key] = replacement
                existing = replacement
        skus = set(existing.get("source_skus") or [])
        for candidate in (existing.get("source_sku"), record.get("source_sku")):
            if candidate:
                skus.add(str(candidate))
        skus.update(str(value) for value in (record.get("source_skus") or []) if value)
        if len(skus) > 1:
            existing["source_skus"] = sorted(skus)
    return list(merged.values()), errors
