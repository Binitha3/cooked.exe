"""Build code.zip from the organized repository without dataset/results."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "code.zip"
ROOT_FILES = ("README.md", "render.yaml")
INCLUDED_DIRS = ("code", "docs", "evaluation", "scripts", "tests")
EXCLUDED_PARTS = {
    ".git",
    ".dist",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "node_modules",
}
EXCLUDED_SUFFIXES = {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".pyc"}


def _included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if EXCLUDED_PARTS.intersection(relative.parts):
        return False
    if path.name == ".DS_Store" or path.suffix.casefold() in EXCLUDED_SUFFIXES:
        return False
    if any(part.casefold().startswith(".env") for part in relative.parts):
        return False
    return True


def build_archive() -> tuple[int, int]:
    files = [ROOT / name for name in ROOT_FILES]
    for directory in INCLUDED_DIRS:
        base = ROOT / directory
        files.extend(path for path in base.rglob("*") if path.is_file() and _included(path))
    files = sorted(set(path for path in files if path.is_file() and _included(path)))

    missing = [path.relative_to(ROOT).as_posix() for path in files if not path.is_file()]
    if missing:
        raise FileNotFoundError(", ".join(missing))

    with tempfile.NamedTemporaryFile(prefix=".code-", suffix=".zip", dir=ROOT, delete=False) as temp:
        temporary_archive = Path(temp.name)
    try:
        with ZipFile(temporary_archive, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
            for path in files:
                archive.write(path, path.relative_to(ROOT).as_posix())
        with ZipFile(temporary_archive) as archive:
            names = set(archive.namelist())
        required = {
            "README.md",
            "render.yaml",
            "evaluation/evaluation_report.md",
            "evaluation/usage_report.md",
        }
        missing_required = required - names
        if missing_required:
            raise ValueError(f"code.zip is missing required files: {sorted(missing_required)}")
        if any(name.startswith("dataset/") or name.startswith("results/") for name in names):
            raise ValueError("code.zip must not include dataset or generated result artifacts")
        os.replace(temporary_archive, ARCHIVE)
    finally:
        temporary_archive.unlink(missing_ok=True)
    return len(files), ARCHIVE.stat().st_size


def main() -> int:
    count, size = build_archive()
    print(f"Built {ARCHIVE.name}: {count} files, {size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
