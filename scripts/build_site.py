from pathlib import Path
import shutil

root = Path(__file__).resolve().parents[1]
out = root / "_dist"
if out.exists():
    shutil.rmtree(out)
shutil.copytree(root / "site", out)
shutil.copytree(root / "data", out / "data")
print(out)
