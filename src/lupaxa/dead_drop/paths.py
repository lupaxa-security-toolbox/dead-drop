"""Path checks shared by archives, recipes, and vault restores."""

from __future__ import annotations

import os
from pathlib import Path

from lupaxa.dead_drop.errors import FilesystemError


def atomic_replace(source: Path, destination: Path) -> None:
    """Replace ``destination`` with ``source`` on the same filesystem."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(source, destination)


def safe_join(root: Path, relative: str) -> Path:
    """Resolve ``relative`` inside ``root`` or reject the path."""
    if relative.startswith(("/", "\\")) or ":" in relative[:3]:
        raise FilesystemError(f"Unsafe path {relative!r}.")
    parts = Path(relative).parts
    if any(part in {"..", ""} or part.startswith("\\") for part in parts):
        raise FilesystemError(f"Unsafe path {relative!r}.")
    candidate = (root / relative).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise FilesystemError(f"Path escapes {root}: {relative}")
    return candidate


def reject_symlink_file(path: Path) -> None:
    """Refuse a symbolic link used as an output or archive member target."""
    if path.is_symlink():
        raise FilesystemError(f"Refusing symbolic link {path}.")


def same_file(left: Path, right: Path) -> bool:
    """Return whether two paths name the same existing file."""
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return False
