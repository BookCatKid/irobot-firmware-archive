from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .util import load_json


def _research_probe_summary(data: dict[str, Any]) -> dict[str, int]:
    probes = data.get("probes")
    hits = data.get("hits")
    records = data.get("records")
    result: dict[str, int] = {}
    if isinstance(probes, list):
        result["probe_count"] = len(probes)
        result["negative_probe_count"] = sum(
            1 for item in probes
            if isinstance(item, dict) and item.get("live") is False
        )
    elif isinstance(data.get("probe_count"), int):
        result["probe_count"] = int(data["probe_count"])
    if isinstance(hits, list):
        result["hit_count"] = len(hits)
    elif isinstance(data.get("hit_count"), int):
        result["hit_count"] = int(data["hit_count"])
    if isinstance(data.get("negative_probe_count"), int):
        result["negative_probe_count"] = int(data["negative_probe_count"])
    elif "negative_probe_count" not in result and "probe_count" in result and "hit_count" in result:
        # The object-sweep ledgers record one URL/object lookup per probe and a
        # hit array containing successful probes. Preserve their already-run
        # negative work instead of reporting zero just because schemas differ.
        result["negative_probe_count"] = max(0, result["probe_count"] - result["hit_count"])
    if isinstance(records, list):
        result["record_count"] = len(records)
    return result


def build_completeness_ledger(
    catalog: dict[str, Any],
    platforms: dict[str, Any],
    research_root: Path,
) -> dict[str, Any]:
    """Build an evidence ledger without pretending the historical universe is known.

    The catalog answers "what artifacts have we recovered?". Research evidence can
    also prove that a historical software state existed without proving a separate
    downloadable OTA object. Keeping those concepts separate is the core invariant.
    """
    rows = catalog.get("firmwares") or []
    archived = [row for row in rows if (row.get("archive") or {}).get("sha256")]
    unique_artifacts: dict[str, dict[str, Any]] = {}
    for row in archived:
        archive = row.get("archive") or {}
        sha = str(archive.get("sha256"))
        item = unique_artifacts.setdefault(sha, {
            "sha256": sha,
            "size": archive.get("size") or row.get("size"),
            "format": archive.get("format"),
            "release_tag": archive.get("release_tag"),
            "asset_url": archive.get("asset_url"),
            "catalog_records": [],
        })
        item["catalog_records"].append({
            "family": row.get("family"),
            "version": row.get("version"),
            "url": row.get("url"),
        })

    formats = Counter((row.get("archive") or {}).get("format") or "unknown" for row in archived)
    historical_path = research_root / "historical-software-state-reconciliation-2026-08-30.json"
    historical = load_json(historical_path, {})
    states = []
    for state in historical.get("states") or []:
        if not isinstance(state, dict):
            continue
        states.append({
            "platform": state.get("platform"),
            "source_sku": state.get("source_sku"),
            "version": state.get("historical_software_version"),
            "evidence_class": state.get("evidence_class"),
            "separate_ota_artifact_proven": bool(state.get("separate_ota_artifact_proven")),
            "probe_result": (state.get("direct_public_filename_probe") or {}).get("result"),
        })

    release_evidence_path = research_root / "official-release-note-artifact-gaps-current.json"
    release_evidence = load_json(release_evidence_path, {})
    gap_dispositions_path = research_root / "official-gap-dispositions-current.json"
    gap_dispositions_data = load_json(gap_dispositions_path, {})
    gap_dispositions = [
        item for item in (gap_dispositions_data.get("entries") or [])
        if isinstance(item, dict)
    ]
    explicit_undispositioned_gaps = [
        item for item in gap_dispositions
        if item.get("disposition") == "unresolved-no-completed-disposition-rule"
    ]
    official_release_gaps = []
    official_release_unresolved_family = []
    official_factory_states = []
    for entry in release_evidence.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        compact = {
            "source_name": entry.get("source_name"),
            "source_url": entry.get("source_url"),
            "candidate_families": entry.get("candidate_families") or [],
            "version": entry.get("version"),
            "release_date_text": entry.get("release_date_text"),
            "classification": entry.get("classification"),
        }
        if entry.get("classification") == "official-ota-release-evidence-unrecovered":
            official_release_gaps.append(compact)
        elif entry.get("classification") == "official-ota-release-evidence-unresolved-family":
            official_release_unresolved_family.append(compact)
        elif entry.get("classification") == "factory-state-only":
            compact["factory_reason"] = entry.get("factory_reason")
            official_factory_states.append(compact)

    platform_rows = platforms.get("platforms") or {}
    mapping_gaps = []
    for family, info in sorted(platform_rows.items()):
        models = info.get("models") or []
        confidence = info.get("confidence") or "unknown"
        if not models or confidence not in {"confirmed", "confirmed-app", "confirmed-app+backend+cdn", "confirmed-app+cdn"}:
            mapping_gaps.append({
                "family": family,
                "confidence": confidence,
                "models": models,
                "known_sku_count": len(info.get("known_skus") or []),
            })

    research_sources = []
    negative_probe_total = 0
    for path in sorted(research_root.glob("*.json")):
        data = load_json(path, {})
        if not isinstance(data, dict):
            continue
        summary = _research_probe_summary(data)
        negative_probe_total += summary.get("negative_probe_count", 0)
        research_sources.append({"file": path.name, **summary})

    proven_missing = [s for s in states if s["separate_ota_artifact_proven"]]
    state_only = [s for s in states if not s["separate_ota_artifact_proven"]]
    current_gap_count = len(official_release_gaps) + len(official_release_unresolved_family)
    # Treat a stale/missing disposition file as incomplete rather than silently
    # reporting 100%. The normal workflows rebuild dispositions immediately
    # before this ledger, but this keeps the metric honest in isolation too.
    missing_disposition_entries = max(0, current_gap_count - len(gap_dispositions))
    undispositioned_gap_count = len(explicit_undispositioned_gaps) + missing_disposition_entries
    disposition_coverage = (
        100.0 if current_gap_count == 0 else round(
            100.0 * max(0, current_gap_count - undispositioned_gap_count) / current_gap_count,
            2,
        )
    )
    return {
        "schema": 1,
        "catalog_updated_at": catalog.get("updated_at"),
        "claim": (
            "Every currently catalogued artifact has archival metadata, but the complete historical set of "
            "iRobot OTA artifacts is not knowable from the surviving public evidence. Historical software-state "
            "evidence, explicit official release evidence, recovered byte-identical aliases, and negative probes "
            "are therefore tracked as separate evidence classes."
        ),
        "rules": [
            "A recovered artifact is identified by the SHA-256 of preserved firmware bytes; catalog aliases do not create extra artifacts.",
            "Official-app softwareVer/history values prove software states, not independently published OTA objects.",
            "An explicit software Version entry on an official rollout/release-note page is independent release evidence, but does not prove one exact package per candidate internal family.",
            "Versions explicitly identified by iRobot as factory-only/no-OTA are software states, not missing OTA artifacts.",
            "A missing OTA artifact requires independent artifact evidence such as deployment metadata, an exact URL/filename, a release/API row, or a verified live object.",
            "Negative filename probes narrow recoverability but do not prove that an artifact never existed.",
        ],
        "summary": {
            "catalog_record_count": len(rows),
            "catalog_records_with_archive_sha256": len(archived),
            "unique_recovered_artifact_sha256_count": len(unique_artifacts),
            "byte_identical_alias_catalog_record_count": len(archived) - len(unique_artifacts),
            "unarchived_catalog_record_count": len(rows) - len(archived),
            "historical_software_state_count": len(states),
            "historical_state_only_count": len(state_only),
            "independently_proven_missing_ota_artifact_count": len(proven_missing),
            "official_release_evidence_gap_count": len(official_release_gaps),
            "official_release_unresolved_family_count": len(official_release_unresolved_family),
            "official_factory_state_only_count": len(official_factory_states),
            "recorded_negative_probe_count": negative_probe_total,
            "official_gap_disposition_count": len(gap_dispositions),
            "official_gap_undispositioned_count": undispositioned_gap_count,
            "known_evidence_disposition_coverage_percent": disposition_coverage,
            "exhausted_or_unrecoverable_count": 0,
            "platform_mapping_gap_count": len(mapping_gaps),
            "formats": dict(sorted(formats.items())),
        },
        "recovered_artifacts": sorted(unique_artifacts.values(), key=lambda x: x["sha256"]),
        "historical_state_only": state_only,
        "independently_proven_missing_ota_artifacts": proven_missing,
        "official_release_evidence_gaps": official_release_gaps,
        "official_release_unresolved_family": official_release_unresolved_family,
        "official_factory_state_only": official_factory_states,
        "exhausted_or_unrecoverable": [],
        "official_gap_dispositions": gap_dispositions,
        "platform_mapping_gaps": mapping_gaps,
        "research_sources": research_sources,
    }
