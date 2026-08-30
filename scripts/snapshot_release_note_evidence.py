#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from irobot_firmware.catalog import load_catalog
from irobot_firmware.discover import release_note_entries
from irobot_firmware.util import load_json


def _candidate_families(notes: dict[str, Any]) -> list[str]:
    explicit = [str(value) for value in notes.get("evidence_families", []) if value]
    if explicit:
        return sorted(set(explicit))
    return sorted({str(item.get("family")) for item in notes.get("families", []) if item.get("family")})


def _row_versions(row: dict[str, Any]) -> set[str]:
    values = {str(row.get("version") or "")}
    values.update(str(value) for value in row.get("version_aliases", []) if value)
    # release-notes-api rows use the release-note version as the *input* state
    # passed to the content API. The API can return a different target package,
    # so that field is not an alias for the archived artifact. Direct/object
    # probes, on the other hand, can retain the release-note version that
    # generated the exact filename they recovered.
    if row.get("release_notes_version") and row.get("source") != "release-notes-api":
        values.add(str(row["release_notes_version"]))
    return {value for value in values if value}


def _numeric_version_key(value: str) -> tuple[int, ...] | None:
    parts = value.split(".")
    if not parts or not all(part.isdigit() for part in parts):
        return None
    numbers = [int(part) for part in parts]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    return tuple(numbers)


def _matching_catalog_rows(catalog: dict[str, Any], families: list[str], version: str) -> list[dict[str, Any]]:
    matches = []
    wanted_numeric = _numeric_version_key(version)
    for row in catalog.get("firmwares", []):
        if families and str(row.get("family")) not in families:
            continue
        row_versions = _row_versions(row)
        exact = version in row_versions
        numeric = bool(
            wanted_numeric is not None
            and any(_numeric_version_key(candidate) == wanted_numeric for candidate in row_versions)
        )
        if exact or numeric:
            matches.append({
                "family": row.get("family"),
                "version": row.get("version"),
                "archive_sha256": (row.get("archive") or {}).get("sha256"),
                "release_tag": (row.get("archive") or {}).get("release_tag"),
            })
    return matches


def build_snapshot(config: dict[str, Any], catalog: dict[str, Any]) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for notes in config.get("release_note_probes", []):
        families = _candidate_families(notes)
        source: dict[str, Any] = {
            "name": notes.get("name"),
            "url": notes.get("url"),
            "candidate_families": families,
        }
        try:
            parsed = release_note_entries(str(notes["url"]))
        except Exception as exc:
            source["error"] = f"{type(exc).__name__}: {exc}"
            errors.append({"name": notes.get("name"), "url": notes.get("url"), "error": source["error"]})
            sources.append(source)
            continue
        source["entry_count"] = len(parsed)
        sources.append(source)
        for entry in parsed:
            version = str(entry["version"])
            matches = _matching_catalog_rows(catalog, families, version)
            if entry.get("factory_only"):
                classification = "factory-state-only"
            elif matches:
                classification = "recovered-release"
            else:
                classification = "official-ota-release-evidence-unrecovered"
            entries.append({
                "source_name": notes.get("name"),
                "source_url": notes.get("url"),
                "candidate_families": families,
                "version": version,
                "release_date_text": entry.get("release_date_text"),
                "factory_only": bool(entry.get("factory_only")),
                "factory_reason": entry.get("factory_reason"),
                "classification": classification,
                "matching_catalog_rows": matches,
            })
    return {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": (
            "Explicit iRobot support-page Version headings are treated as independent release evidence. "
            "Dotted dates are ignored. Entries explicitly identified as factory-only/no-OTA are software-state "
            "evidence only and are excluded from unrecovered OTA-artifact counts."
        ),
        "sources": sources,
        "entries": entries,
        "errors": errors,
        "summary": {
            "source_count": len(sources),
            "source_error_count": len(errors),
            "entry_count": len(entries),
            "recovered_release_count": sum(x["classification"] == "recovered-release" for x in entries),
            "factory_state_only_count": sum(x["classification"] == "factory-state-only" for x in entries),
            "official_ota_release_evidence_unrecovered_count": sum(
                x["classification"] == "official-ota-release-evidence-unrecovered" for x in entries
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Snapshot official iRobot software-release evidence")
    parser.add_argument("--config", type=Path, default=Path("config/discovery.json"))
    parser.add_argument("--catalog", type=Path, default=Path("data/catalog.json"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/research/official-release-note-artifact-gaps-current.json"),
    )
    args = parser.parse_args()
    snapshot = build_snapshot(load_json(args.config, {}), load_catalog(args.catalog))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Keep generated output byte-stable when the underlying support-page
    # evidence has not changed. This lets the daily workflow refresh the
    # snapshot without creating a meaningless timestamp-only commit.
    previous = load_json(args.output, {})
    if isinstance(previous, dict) and previous.get("generated_at"):
        comparable_previous = dict(previous)
        comparable_snapshot = dict(snapshot)
        comparable_previous.pop("generated_at", None)
        comparable_snapshot.pop("generated_at", None)
        if comparable_previous == comparable_snapshot:
            snapshot["generated_at"] = previous["generated_at"]
    args.output.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    summary = snapshot["summary"]
    print(
        f"{summary['entry_count']} official release-note entries; "
        f"{summary['recovered_release_count']} recovered; "
        f"{summary['factory_state_only_count']} factory-only; "
        f"{summary['official_ota_release_evidence_unrecovered_count']} unrecovered OTA-release evidence; "
        f"errors={summary['source_error_count']}"
    )
    return 1 if snapshot["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
