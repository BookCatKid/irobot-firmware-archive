from __future__ import annotations

import concurrent.futures
import itertools
import time
from pathlib import Path
from typing import Iterable

from .discover import direct_probe


def classic_versions(year_start: int, year_end: int, patch_max: int = 15) -> Iterable[str]:
    """Generate both padded and unpadded YY.WW.patch forms used by classic iRobot builds."""
    seen: set[str] = set()
    for year, week, patch in itertools.product(range(year_start, year_end + 1), range(1, 54), range(0, patch_max + 1)):
        for version in (f"{year}.{week}.{patch}", f"{year}.{week:02d}.{patch:02d}", f"{year}.{week}.{patch:02d}"):
            if version not in seen:
                seen.add(version)
                yield version


def semantic_versions(major_max: int, minor_max: int, patch_max: int) -> Iterable[str]:
    for major, minor, patch in itertools.product(range(major_max + 1), range(minor_max + 1), range(patch_max + 1)):
        yield f"{major}.{minor}.{patch}"


def numeric_versions(start: int, end: int, width: int = 0) -> Iterable[str]:
    """Generate an inclusive integer token range used by legacy OTA filenames.

    Old iRobot packages such as ``marconiv327.signed`` and
    ``roomba9xxv2444.signed`` use opaque numeric filename tokens that are not
    reliably derivable from the user-visible release version.
    """
    if end < start:
        return
    for value in range(start, end + 1):
        yield f"{value:0{width}d}" if width else str(value)


def scan_direct(
    family: str,
    template: str,
    versions: Iterable[str],
    workers: int = 4,
    max_probes: int | None = None,
    pause: float = 0.0,
) -> list[dict]:
    candidates = list(itertools.islice(versions, max_probes)) if max_probes else list(versions)

    def probe(version: str):
        if pause:
            time.sleep(pause)
        return direct_probe(family, version, template)

    hits: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(probe, version): version for version in candidates}
        for future in concurrent.futures.as_completed(futures):
            try:
                hit = future.result()
                if hit:
                    hits.append(hit)
                    print(f"FOUND {family} {hit['version']} {hit['url']}", flush=True)
            except Exception as exc:
                print(f"WARN {family} {futures[future]}: {exc}", flush=True)
    return sorted(hits, key=lambda x: x["version"])
