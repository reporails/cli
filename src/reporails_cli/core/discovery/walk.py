"""Symlink-following file walkers for instruction discovery.

`Path.rglob` on Python 3.12 does not descend into symlinked directories
(`recurse_symlinks=True` is 3.13-only). The project pins `>=3.12,<3.14`,
so bulk-discovery sites use these helpers instead — they walk via
`os.walk(followlinks=True)` and track canonical inode paths to break
symlink cycles.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path


def walk_markdown(root: Path) -> Iterator[Path]:
    """Yield every regular `.md` file under root, following symlinks safely."""
    yield from _walk(root, lambda p: p.suffix == ".md")


def walk_files(root: Path, predicate: Callable[[Path], bool] | None = None) -> Iterator[Path]:
    """Yield every regular file under root, following symlinks safely.

    Optional `predicate` further filters the yielded files (e.g. text-file
    detection for the regex runner's catch-all fallback).
    """
    yield from _walk(root, predicate)


def _walk(root: Path, predicate: Callable[[Path], bool] | None) -> Iterator[Path]:
    """Shared walker — `os.walk(followlinks=True)` with realpath cycle tracking."""
    visited_real: set[str] = set()
    try:
        visited_real.add(os.path.realpath(root))
    except OSError:
        return

    for dirpath, dirs, files in os.walk(root, followlinks=True):
        kept: list[str] = []
        for name in dirs:
            full = os.path.join(dirpath, name)
            try:
                real = os.path.realpath(full)
            except OSError:
                continue
            if real in visited_real:
                continue
            visited_real.add(real)
            kept.append(name)
        dirs[:] = kept

        for filename in files:
            full_path = Path(dirpath) / filename
            if predicate is not None and not predicate(full_path):
                continue
            if not full_path.is_file():
                continue
            yield full_path
