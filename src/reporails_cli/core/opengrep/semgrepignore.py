"""Semgrepignore file handling.

Manages .semgrepignore files for OpenGrep performance.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from reporails_cli.bundled import get_semgrepignore_path


def ensure_semgrepignore(
    target: Path,
    extra_excludes: list[str] | None = None,
) -> Path | None:
    """Ensure .semgrepignore exists in target directory.

    If no .semgrepignore exists, copies the bundled default.
    If extra_excludes are provided, appends them as directory patterns.
    Returns path to created file if created, None if already exists
    (unless extra_excludes required modification).

    Args:
        target: Target directory to scan
        extra_excludes: Additional directory names to exclude (e.g., ["tests", "vendor"])

    Returns:
        Path to created .semgrepignore if created/modified, None otherwise
    """
    target_dir = target if target.is_dir() else target.parent
    existing = target_dir / ".semgrepignore"

    if existing.exists():
        # Append extra excludes to existing file if needed
        if extra_excludes:
            try:
                content = existing.read_text(encoding="utf-8")
                additions = []
                for dirname in extra_excludes:
                    pattern = f"{dirname}/"
                    if pattern not in content:
                        additions.append(pattern)
                if additions:
                    with open(existing, "a", encoding="utf-8") as f:
                        f.write("\n# Extra excludes (reporails)\n")
                        for pattern in additions:
                            f.write(f"{pattern}\n")
                    return existing
            except OSError:
                pass
        return None

    # Copy bundled .semgrepignore to target directory
    bundled = get_semgrepignore_path()
    if bundled.exists():
        try:
            shutil.copy(bundled, existing)
            # Append extra excludes
            if extra_excludes:
                with open(existing, "a", encoding="utf-8") as f:
                    f.write("\n# Extra excludes (reporails)\n")
                    for dirname in extra_excludes:
                        f.write(f"{dirname}/\n")
            return existing  # Return so caller can clean up
        except OSError:
            pass
    return None
