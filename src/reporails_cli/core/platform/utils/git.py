"""The git repository a folder sits in."""

from __future__ import annotations

import os
from pathlib import Path


def git_root(folder: Path) -> Path | None:
    """The nearest folder at or above `folder` that holds a `.git` (a folder, or the file of a worktree), or None.

    `folder` is made absolute but its symlinks are left as written.
    """
    absolute = Path(os.path.abspath(folder))
    return next((candidate for candidate in (absolute, *absolute.parents) if (candidate / ".git").exists()), None)
