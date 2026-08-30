from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .util import load_json, save_json


@dataclass(frozen=True)
class FirmwareKey:
    family: str
    version: str
    url: str

    @property
    def id(self) -> str:
        return f"{self.family}:{self.version}:{self.url}"


def empty_catalog() -> dict[str, Any]:
    return {
        "schema": 1,
        "updated_at": None,
        "firmwares": [],
    }


def load_catalog(path: Path) -> dict[str, Any]:
    return load_json(path, empty_catalog())


def merge_records(catalog: dict[str, Any], records: list[dict[str, Any]]) -> tuple[dict[str, Any], int]:
    items = catalog.setdefault("firmwares", [])
    by_key = {(x.get("family"), x.get("version"), x.get("url")): x for x in items}
    by_url = {x.get("url"): x for x in items if x.get("url")}
    added = 0
    changed = False
    for record in records:
        key = (record.get("family"), record.get("version"), record.get("url"))
        old = by_key.get(key) or by_url.get(record.get("url"))
        if old is None:
            items.append(record)
            by_key[key] = record
            if record.get("url"):
                by_url[record.get("url")] = record
            added += 1
            changed = True
        else:
            # A URL identifies one immutable artifact even when a release-note/API path
            # spells its version differently (22.7.2 vs 22.07.02 vs compact v220702).
            # Keep the established/archived label and retain alternate labels explicitly.
            incoming_version = record.get("version")
            if incoming_version and incoming_version != old.get("version"):
                aliases = old.setdefault("version_aliases", [])
                if incoming_version not in aliases:
                    aliases.append(incoming_version)
                    aliases.sort()
                    changed = True
            if key != (old.get("family"), old.get("version"), old.get("url")):
                alias = {
                    field: record.get(field)
                    for field in ("family", "version", "source", "source_sku", "release_date", "release_notes_url", "release_notes_version")
                    if record.get(field) not in (None, "", [], {})
                }
                alternatives = old.setdefault("alternate_discoveries", [])
                if alias and alias not in alternatives:
                    alternatives.append(alias)
                    changed = True
            # Firmware identity is immutable. A recurring discovery pass can reach the same
            # object through several equivalent probes, often with a fresh discovered_at or a
            # different source_software_ver. Preserve the first evidence rather than making
            # catalog history depend on thread completion order. New discovery may still enrich
            # an existing row by filling fields that were previously absent/empty.
            for field, value in record.items():
                if field in {"archive", "analysis", "discovered_at"}:
                    continue
                if (field not in old or old.get(field) in (None, "", [], {})) and value not in (None, "", [], {}):
                    old[field] = value
                    changed = True
    items.sort(key=lambda x: (x.get("family", ""), x.get("version", ""), x.get("url", "")))
    if changed:
        catalog["updated_at"] = datetime.now(timezone.utc).isoformat()
    return catalog, added


def write_catalog(path: Path, catalog: dict[str, Any]) -> None:
    save_json(path, catalog)
