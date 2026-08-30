from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .util import load_json


AUDIO_SUFFIXES = {".opus", ".ogg", ".wav", ".mp3", ".flac", ".aac", ".m4a"}


def iter_audio_entries(value: Any) -> Iterable[dict[str, Any]]:
    """Yield hashed audio files from any deep filesystem analysis manifest.

    The robot OTA already preserves the audio bytes. This iterator deliberately
    indexes metadata only, so a sound can be traced across firmware generations
    without duplicating media assets into Git history.
    """
    if isinstance(value, dict):
        path = value.get("path")
        if (
            isinstance(path, str)
            and value.get("type") == "file"
            and value.get("sha256")
            and Path(path).suffix.lower() in AUDIO_SUFFIXES
        ):
            yield value
        for child in value.values():
            yield from iter_audio_entries(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_audio_entries(child)


def audio_path_metadata(path: str) -> dict[str, str]:
    normalized = path.strip("/")
    parts = normalized.split("/")
    result = {"category": "other"}
    try:
        audio_idx = parts.index("audio")
    except ValueError:
        return result
    tail = parts[audio_idx + 1 :]
    if tail[:1] == ["songs"]:
        result["category"] = "song"
    elif tail[:1] == ["languages"] and len(tail) >= 3:
        result["category"] = "voice-prompt"
        result["language"] = tail[1]
    else:
        result["category"] = "other-irobot-audio"
    return result


def audio_semantic_key(path: str) -> tuple[str, str, str, str]:
    meta = audio_path_metadata(path)
    return (
        meta["category"],
        meta.get("language", ""),
        Path(path).stem,
        Path(path).suffix.lower().lstrip("."),
    )


def build_audio_index(catalog: dict[str, Any], data_root: Path) -> dict[str, Any]:
    sounds: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    representatives: dict[tuple[str, str, str, str], tuple[tuple[Any, ...], dict[str, Any]]] = {}
    seen_preserved_file: set[tuple[str, str, str]] = set()
    seen_direct_preserved_file: set[tuple[str, str, str]] = set()
    all_hashes: set[str] = set()
    parent_firmwares: set[str] = set()
    occurrence_count = 0
    for record in catalog.get("firmwares") or []:
        archive = record.get("archive") or {}
        manifest_rel = archive.get("manifest")
        if not manifest_rel:
            continue
        manifest_path = data_root / str(manifest_rel)
        if not manifest_path.is_file():
            continue
        manifest = load_json(manifest_path, {})

        # Choose one deterministic, directly extractable SquashFS occurrence
        # for each semantic sound.  Restricting the download representative to
        # top-level component filesystem analysis means the build tooling can
        # range-download one preserved component and extract the file without
        # having to reverse nested CPIO/tar containers on every Pages build.
        for component in manifest.get("components") or []:
            if not isinstance(component, dict):
                continue
            filesystem = component.get("filesystem_analysis") or {}
            for entry in filesystem.get("files") or []:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path")
                if (
                    not isinstance(path, str)
                    or entry.get("type") != "file"
                    or not entry.get("sha256")
                    or Path(path).suffix.lower() not in AUDIO_SUFFIXES
                ):
                    continue
                sha256 = str(entry["sha256"])
                parent_sha = str(archive.get("sha256") or manifest_rel)
                preserved_identity = (parent_sha, path, sha256)
                if preserved_identity in seen_direct_preserved_file:
                    continue
                seen_direct_preserved_file.add(preserved_identity)
                key = audio_semantic_key(path)
                category, language, name, extension = key
                release_date = str(record.get("release_date") or "")
                rank = (
                    bool(release_date),
                    release_date,
                    str(record.get("family") or ""),
                    str(record.get("version") or ""),
                    path,
                )
                representative = {
                    "sha256": sha256,
                    "size": int(entry.get("size") or 0),
                    "source_path": path,
                    "parent_family": str(record.get("family") or ""),
                    "parent_version": str(record.get("version") or ""),
                    "parent_release_tag": str(archive.get("release_tag") or ""),
                    "parent_asset_url": str(archive.get("asset_url") or record.get("url") or ""),
                    "component_index": component.get("index"),
                    "component_payload_offset": component.get("payload_offset"),
                    "component_size": component.get("size"),
                    "component_sha256": component.get("sha256"),
                }
                current = representatives.get(key)
                if current is None or rank > current[0]:
                    representatives[key] = (rank, representative)

        for entry in iter_audio_entries(manifest):
            path = str(entry["path"])
            sha256 = str(entry["sha256"])
            parent_sha = str(archive.get("sha256") or manifest_rel)
            preserved_identity = (parent_sha, path, sha256)
            # The same physical parent package may have multiple catalog aliases.
            if preserved_identity in seen_preserved_file:
                continue
            seen_preserved_file.add(preserved_identity)
            occurrence_count += 1
            all_hashes.add(sha256)
            parent_firmwares.add(parent_sha)
            category, language, name, extension = audio_semantic_key(path)
            key = (category, language, name, extension)
            sound = sounds.setdefault(key, {
                "category": category,
                "name": name,
                "extension": extension,
                "occurrence_count": 0,
                "_hashes": set(),
                "_families": set(),
                "_parents": set(),
                "_sizes": set(),
                "_observations": [],
            })
            if language:
                sound["language"] = language
            sound["occurrence_count"] += 1
            sound["_hashes"].add(sha256)
            sound["_families"].add(str(record.get("family") or ""))
            sound["_parents"].add(parent_sha)
            sound["_sizes"].add(int(entry.get("size") or 0))
            release_date = record.get("release_date")
            if release_date:
                sound["_observations"].append({
                    "date": str(release_date),
                    "family": str(record.get("family") or ""),
                    "version": str(record.get("version") or ""),
                    "release_tag": str(archive.get("release_tag") or ""),
                })

    entries: list[dict[str, Any]] = []
    for key, sound in sounds.items():
        sizes = sound.pop("_sizes")
        hashes = sound.pop("_hashes")
        families = sound.pop("_families")
        parents = sound.pop("_parents")
        observations = sound.pop("_observations")
        sound.update({
            "unique_variant_count": len(hashes),
            "parent_firmware_count": len(parents),
            "families": sorted(families),
            "min_size": min(sizes) if sizes else 0,
            "max_size": max(sizes) if sizes else 0,
        })
        if observations:
            observations.sort(key=lambda x: (x["date"], x["family"], x["version"]))
            sound["first_seen"] = observations[0]
            sound["last_seen"] = observations[-1]
        representative = representatives.get(key)
        if representative:
            sound["representative"] = representative[1]
        entries.append(sound)
    entries.sort(key=lambda x: (x["category"], x.get("language", ""), x["name"], x["extension"]))
    languages = Counter(x["language"] for x in entries if x.get("language"))
    categories = Counter(x["category"] for x in entries)
    extensions = Counter(x["extension"] for x in entries)
    families = Counter(family for x in entries for family in x["families"])
    songs = sorted({x["name"] for x in entries if x["category"] == "song"})
    return {
        "schema": 1,
        "source": "deep filesystem analysis of archived iRobot robot firmware",
        "catalog_updated_at": catalog.get("updated_at"),
        "note": (
            "Semantic metadata index plus one directly extractable representative per sound. Exact per-file "
            "SHA-256/path provenance remains in each firmware analysis manifest. Representatives point back to "
            "the original archived firmware so the selected file can be locally extracted and hash-verified."
        ),
        "summary": {
            "audio_file_occurrence_count": occurrence_count,
            "semantic_sound_count": len(entries),
            "unique_sha256_count": len(all_hashes),
            "parent_firmware_count": len(parent_firmwares),
            "language_count": len(languages),
            "languages": dict(sorted(languages.items())),
            "categories": dict(sorted(categories.items())),
            "extensions": dict(sorted(extensions.items())),
            "families": dict(sorted(families.items())),
            "song_names": songs,
            "unique_song_name_count": len(songs),
        },
        "sounds": entries,
    }
