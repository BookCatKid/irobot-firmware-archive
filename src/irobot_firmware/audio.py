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


def build_audio_index(catalog: dict[str, Any], data_root: Path) -> dict[str, Any]:
    sounds: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    seen_preserved_file: set[tuple[str, str, str]] = set()
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
            meta = audio_path_metadata(path)
            category = meta["category"]
            language = meta.get("language", "")
            name = Path(path).stem
            extension = Path(path).suffix.lower().lstrip(".")
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
    for sound in sounds.values():
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
            "Semantic metadata index only; exact per-file SHA-256/path provenance remains in each firmware analysis "
            "manifest and the audio bytes remain preserved inside the original archived firmware assets."
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
