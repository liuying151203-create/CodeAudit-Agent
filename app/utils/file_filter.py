from pathlib import Path

IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "target", "dist", "__pycache__", ".mypy_cache"}
SUPPORTED_EXTENSIONS = {".java", ".py"}


def should_scan_file(path: Path) -> bool:
    parts = set(path.parts)
    return not (parts & IGNORED_DIRS) and path.suffix in SUPPORTED_EXTENSIONS
