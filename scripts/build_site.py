from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
out = root / "_dist"
if out.exists():
    shutil.rmtree(out)
shutil.copytree(root / "site", out)
shutil.copytree(root / "data", out / "data")
shutil.copy2(root / "config" / "platforms.json", out / "data" / "platforms.json")

# Materialize directly-downloadable audio clips into site/audio -> _dist/audio.
# Local / offline builds use placeholders so `python scripts/build_site.py`
# stays fast and doesn't need network or unsquashfs. CI with network &
# unsquashfs can pre-run `scripts/build_audio_packs.py` without --force-placeholder
# to replace placeholders with real bytes before this step.
audio_packs = root / "scripts" / "build_audio_packs.py"
if audio_packs.exists():
    try:
        audio_src = root / "site" / "audio"
        # Only regenerate placeholders if the directory doesn't already exist
        # (e.g. CI may have already populated it with real extracts).
        if not audio_src.is_dir():
            subprocess.run([sys.executable, str(audio_packs), "--force-placeholder"], check=False)
        if audio_src.is_dir():
            shutil.copytree(audio_src, out / "audio", dirs_exist_ok=True)
    except Exception as exc:
        print(f"warn: audio pack build skipped ({exc})", file=sys.stderr)

print(out)
