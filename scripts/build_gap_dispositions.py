#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_SNAPSHOT = Path("data/research/official-release-note-artifact-gaps-current.json")
DEFAULT_OUTPUT = Path("data/research/official-gap-dispositions-current.json")


# These rules describe the strongest *completed* recovery work for each
# official support-page source. They deliberately do not turn a negative URL
# probe into proof that a historical package never existed.
SOURCE_RULES: dict[str, dict[str, Any]] = {
    "j-series": {
        "versions": ["1.4.8", "1.4.6"],
        "disposition": "tested-known-filename-skeleton-no-live-object",
        "evidence": [
            "official-release-gap-exact-object-probes-2026-08-30.json",
            "android-historical-app-ota-followup-2026-08-30.json",
        ],
        "note": "Official release evidence remains, but established Ruby/Sapphire/Stingray public filename forms and targeted historical-app strings yielded no recoverable exact object.",
    },
    "i-series": {
        "versions": ["1.0.3", "1.4"],
        "disposition": "tested-known-filename-skeleton-no-live-object",
        "evidence": [
            "i-series-release-note-gap-probes-2026-08-30.json",
            "android-historical-app-ota-followup-2026-08-30.json",
        ],
        "note": "Official release evidence remains; established Lewis/Daredevil filename forms and targeted historical-app evidence did not identify live public bytes.",
    },
    "roomba-100": {
        "versions": ["8.4.1", "7.3.1", "7.2.3", "6.3.1", "6.2.5", "3.1.19", "3.1.16"],
        "disposition": "unresolved-package-skeleton-after-bounded-search",
        "evidence": [
            "modern-fixed-branch-build-sweep-2026-08-30.json",
            "modern-release-gap-known-suffix-probes-2026-08-30.json",
            "official-release-gap-v2-matrix-2026-08-30.json",
        ],
        "note": "Known C3/V3 modern branch grammar was searched with bounded evidence-derived builds/suffixes. Remaining releases require a different historical skeleton/build identity or a new source lead.",
    },
    "roomba-200": {
        "versions": ["8.4.1", "7.5.2", "7.3.6", "7.3.3", "7.3.1", "6.3.1", "6.2.5", "3.1.19", "3.1.16"],
        "disposition": "unresolved-package-skeleton-after-bounded-search",
        "evidence": [
            "modern-fixed-branch-build-sweep-2026-08-30.json",
            "modern-release-gap-known-suffix-probes-2026-08-30.json",
            "official-release-gap-v2-matrix-2026-08-30.json",
        ],
        "note": "Known CC_205 modern package grammar recovered newer releases but not these official older states; a prior hardware/package skeleton is not yet evidenced.",
    },
    "roomba-plus-400": {
        "versions": ["8.6.2", "8.4.1", "7.5.2", "7.3.6", "7.3.3", "7.3.1", "7.2.3", "6.3.1", "6.2.5"],
        "disposition": "unresolved-package-skeleton-after-bounded-search",
        "evidence": [
            "modern-fixed-branch-build-sweep-2026-08-30.json",
            "modern-release-gap-known-suffix-probes-2026-08-30.json",
            "official-release-gap-v2-matrix-2026-08-30.json",
        ],
        "note": "Known C4 modern package grammar recovered newer releases but not these official older states; a prior hardware/package skeleton is not yet evidenced.",
    },
    "roomba-plus-500": {
        "versions": ["9.3.5", "7.3.6", "7.3.3", "7.3.1", "7.2.3", "6.3.1", "6.2.5"],
        "disposition": "unresolved-package-skeleton-after-bounded-search",
        "evidence": [
            "505-older-official-gap-field-sweep-2026-08-30.json",
            "505-official-gap-field-sweep-2026-08-30.json",
            "official-release-gap-v2-matrix-2026-08-30.json",
        ],
        "note": "The observed C11e/mcu35/branch-3.8 family was bounded across evidence-derived fields; remaining older versions produced no live object and require a different skeleton or exact device identity.",
    },
    "roomba-max-700": {
        "versions": ["9.3.5", "9.3.4", "8.6.8", "8.6.5", "8.4.4", "7.5.2", "7.3.6", "7.3.3", "7.3.1", "6.4.3"],
        "disposition": "unresolved-package-skeleton-after-bounded-search",
        "evidence": [
            "705-expanded-official-gap-field-sweep-2026-08-30.json",
            "705-official-gap-field-sweep-2026-08-30.json",
            "official-release-gap-v2-matrix-2026-08-30.json",
            "705-public-device-state-evidence-2026-08-30.json",
        ],
        "note": "Observed V11/C11m hardware grammars were exhaustively bounded over the evidenced field ranges; remaining versions require another skeleton or exact real-device identity.",
    },
    "roomba-essential-original": {
        "versions": ["1.1.5"],
        "disposition": "tested-known-filename-skeleton-no-live-object",
        "evidence": ["official-release-gap-exact-object-probes-2026-08-30.json"],
        "note": "The zero-padded Congo naming form that recovered 1.1.14 and 1.1.22 was tested for the remaining official release and is not live at that exact object name.",
    },
    "roomba-essential-2": {
        "versions": ["1.2.6", "1.2.4", "1.2.2"],
        "disposition": "unresolved-hardware-family",
        "evidence": [
            "essential2-altadena-and-listing-followup-2026-08-30.json",
            "official-release-gap-v2-matrix-2026-08-30.json",
        ],
        "note": "Official Essential 2 release versions are known, but the app/default-SKU evidence does not establish their OTA family or package grammar. They are intentionally not mapped to Congo.",
    },
    "wifi-600-800-series": {
        "versions": ["3.2.0", "3.1.0"],
        "disposition": "tested-known-filename-skeleton-no-live-object",
        "evidence": ["official-release-gap-exact-object-probes-2026-08-30.json"],
        "note": "Established Marconi/Ningbo public naming variants were tested for the official versions without a live object. Other historical naming remains possible if new evidence emerges.",
    },
    "roomba-e-series": {
        "versions": ["3.4.62", "3.4.42"],
        "disposition": "tested-known-filename-skeleton-no-live-object",
        "evidence": [
            "official-release-gap-exact-object-probes-2026-08-30.json",
            "legacy-v1-deployment-object-probe-2026-08-29.json",
            "e-series-3.4.62-real-device-evidence-2026-08-30.json",
        ],
        "note": "Official e-series release evidence and historical deployment metadata exist, but tested Aero public object forms for these exact versions are not live. aero3562.signed is separately archived as 3.5.62 and is not evidence for 3.4.62.",
    },
    "braava-jet": {
        "versions": ["4.54", "4.50"],
        "disposition": "tested-known-filename-skeleton-no-live-object",
        "evidence": ["essential2-altadena-and-listing-followup-2026-08-30.json"],
        "note": "Exact Altadena filename forms derived from preserved 4.63 and app-bundled 4.60 conventions were tested for 4.50/4.54 with no live object.",
    },
}


def build(snapshot: dict[str, Any]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for entry in snapshot.get("entries") or []:
        classification = entry.get("classification")
        if classification not in {
            "official-ota-release-evidence-unrecovered",
            "official-ota-release-evidence-unresolved-family",
        }:
            continue
        source_name = str(entry.get("source_name") or "")
        rule = SOURCE_RULES.get(source_name)
        if rule is not None and str(entry.get("version") or "") not in set(rule.get("versions") or []):
            rule = None
        if rule is None:
            disposition = "unresolved-no-completed-disposition-rule"
            evidence: list[str] = []
            note = "No completed evidence-backed disposition rule has been recorded for this source yet."
        else:
            disposition = str(rule["disposition"])
            evidence = list(rule.get("evidence") or [])
            note = str(rule.get("note") or "")
        entries.append({
            "source_name": source_name,
            "source_url": entry.get("source_url"),
            "version": entry.get("version"),
            "candidate_families": entry.get("candidate_families") or [],
            "release_evidence_classification": classification,
            "disposition": disposition,
            "evidence_files": evidence,
            "note": note,
        })

    unresolved = [x for x in entries if x["disposition"] == "unresolved-no-completed-disposition-rule"]
    return {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": (
            "Every official release-note entry whose bytes are not currently recovered receives a separate evidence-backed disposition. "
            "A tested filename/skeleton disposition means only that the documented search space has been exhausted; it is not proof that a historical artifact never existed."
        ),
        "entries": entries,
        "summary": {
            "gap_entry_count": len(entries),
            "dispositioned_gap_entry_count": len(entries) - len(unresolved),
            "undispositioned_gap_entry_count": len(unresolved),
            "known_evidence_disposition_coverage_percent": (
                100.0 if not entries else round(100.0 * (len(entries) - len(unresolved)) / len(entries), 2)
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build evidence-backed dispositions for unresolved official firmware releases")
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--allow-undispositioned",
        action="store_true",
        help="Write the ledger and exit successfully even when new gaps still need research",
    )
    args = parser.parse_args()
    snapshot = json.loads(args.snapshot.read_text())
    result = build(snapshot)
    previous = {}
    if args.output.exists():
        try:
            previous = json.loads(args.output.read_text())
        except Exception:
            previous = {}
    if previous.get("generated_at"):
        old = dict(previous)
        new = dict(result)
        old.pop("generated_at", None)
        new.pop("generated_at", None)
        if old == new:
            result["generated_at"] = previous["generated_at"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    summary = result["summary"]
    print(
        f"{summary['dispositioned_gap_entry_count']}/{summary['gap_entry_count']} official gaps dispositioned; "
        f"coverage={summary['known_evidence_disposition_coverage_percent']}%; "
        f"undispositioned={summary['undispositioned_gap_entry_count']}"
    )
    return 0 if args.allow_undispositioned else (1 if summary["undispositioned_gap_entry_count"] else 0)


if __name__ == "__main__":
    raise SystemExit(main())
