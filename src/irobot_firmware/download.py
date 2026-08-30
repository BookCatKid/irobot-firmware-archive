from __future__ import annotations

import shutil
import urllib.request
from pathlib import Path

from .util import sha256_file


def download(url: str, dest: Path, expected_size: int | None = None) -> dict[str, object]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "irobot-firmware-archive/0.1"})
    with urllib.request.urlopen(req, timeout=120) as response, partial.open("wb") as out:
        shutil.copyfileobj(response, out, length=1024 * 1024)
    size = partial.stat().st_size
    if expected_size is not None and size != expected_size:
        partial.unlink(missing_ok=True)
        raise RuntimeError(f"download size mismatch: expected {expected_size}, got {size}")
    partial.replace(dest)
    return {"size": size, "sha256": sha256_file(dest)}
