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
    for record in records:
        key = (record.get("family"), record.get("version"), record.get("url"))
        old = by_key.get(key)
        if old is None:
            items.append(record)
            by_key[key] = record
            added += 1
        else:
            # Never erase archival state with a discovery refresh.
            archive = old.get("archive")
            analysis = old.get("analysis")
            old.update(record)
            if archive is not None:
                old["archive"] = archive
            if analysis is not None:
                old["analysis"] = analysis
    items.sort(key=lambda x: (x.get("family", ""), x.get("version", ""), x.get("url", "")))
    catalog["updated_at"] = datetime.now(timezone.utc).isoformat()
    return catalog, added


def write_catalog(path: Path, catalog: dict[str, Any]) -> None:
    save_json(path, catalog)
