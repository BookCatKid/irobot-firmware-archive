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
    added = 0
    changed = False
    for record in records:
        key = (record.get("family"), record.get("version"), record.get("url"))
        old = by_key.get(key)
        if old is None:
            items.append(record)
            by_key[key] = record
            added += 1
            changed = True
        else:
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
