"""Semgrepignore file handling.

Manages .semgrepignore files for OpenGrep performance.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from reporails_cli.bundled import get_semgrepignore_path


def ensure_semgrepignore(target: Path) -> Path | None:
    """Ensure .semgrepignore exists in target directory.

    If no .semgrepignore exists, copies the bundled default.
    Returns path to created file if created, None if already exists.

    Args:
        target: Target directory to scan

    Returns:
        Path to created .semgrepignore if created, None otherwise
    """
    target_dir = target if target.is_dir() else target.parent
    existing = target_dir / ".semgrepignore"
    if existing.exists():
        return None

    # Copy bundled .semgrepignore to target directory
    bundled = get_semgrepignore_path()
    if bundled.exists():
        try:
            shutil.copy(bundled, existing)
            return existing  # Return so caller can clean up
        except OSError:
            pass
    return None
