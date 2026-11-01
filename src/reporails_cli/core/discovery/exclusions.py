"""The exclusion set of one run: the folders and file globs the user left out, and the built-in defaults."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

from reporails_cli.core.discovery.walk import child_real, safe_resolve
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.dto.discovery import RunExclusions
from reporails_cli.core.platform.dto.exclusion import FolderValue
from reporails_cli.core.platform.policy.exclusion import parse_folder_value
from reporails_cli.core.platform.utils.utils import matches_any_glob


def _roots_of(root: Path) -> tuple[Path, ...]:
    """The root as given and, when different, resolved."""
    resolved = safe_resolve(root)
    return (root,) if resolved == root else (root, resolved)


def no_exclusions(root: Path) -> RunExclusions:
    """No user exclusions; walks still prune the built-in defaults."""
    return RunExclusions(root=root, roots=_roots_of(root))


def parse_run_exclusions(root: Path, dirs: Iterable[str], files: Iterable[str]) -> RunExclusions:
    """The exclusions of the folder values `dirs` and file globs `files`, without repeats, in the order given."""
    roots = (root, safe_resolve(root))
    folders = dict.fromkeys(v for v in (parse_folder_value(d, roots) for d in dirs) if v is not None)
    return RunExclusions(
        root=root, roots=(root,) if roots[1] == root else roots, dirs=tuple(folders), files=tuple(dict.fromkeys(files))
    )


def with_named(exclusions: RunExclusions, paths: Iterable[Path]) -> RunExclusions:
    """A copy of `exclusions` that also treats `paths` as named by the user."""
    return replace(exclusions, named=exclusions.named | {safe_resolve(p) for p in paths})


def covers(exclusions: RunExclusions, path: Path) -> bool:
    """True when a walk never reaches `path`: it, or a folder above it below the root, is skipped.

    Tests each segment from the root down for a built-in default, then for a user folder. A
    file at the end of `path` is listed by a walk, not skipped like a folder.
    """
    for root in exclusions.roots:
        if path.is_relative_to(root):
            parts = path.relative_to(root).parts
            folder = os.fspath(root)
            real = os.fspath(exclusions.roots[-1])
            for depth, part in enumerate(parts, 1):
                folder = os.path.join(folder, part)
                pruned = exclusions.default_pruned(part)
                if not pruned and exclusions.dirs:
                    real = child_real(folder, part, real, os.path.islink(folder))
                    pruned = exclusions.user_pruned(folder, real)
                if pruned:
                    return depth < len(parts) or not os.path.isfile(folder)
            return False
    return False


def leaves_out(exclusions: RunExclusions, path: Path) -> bool:
    """True when `path` sits in a folder the user left out or matches a file glob the user left out.

    A folder name is matched at any depth; a folder path is relative to the root. A named path is
    never left out. Built-in defaults never count. The path is tried as given and resolved,
    against the root as given and resolved.
    """
    if not exclusions.dirs and not exclusions.files:
        return False
    resolved = safe_resolve(path)
    if exclusions.named and resolved in exclusions.named:
        return False
    return _hit(exclusions, path, resolved, exclusions.dirs, exclusions.files)


def record_patterns(exclusions: RunExclusions, *, narrowed: bool = False) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The `(folders, file globs)` to report: every user pattern, sorted, without repeats.

    With `narrowed` (the run covers only the named files) a pattern that a named file matches is
    dropped; a pattern that matches nothing stays.
    """
    named = exclusions.named if narrowed else frozenset()
    dirs = sorted(
        {d.text for d in exclusions.dirs if not any(_hit(exclusions, p, safe_resolve(p), (d,), ()) for p in named)}
    )
    files = sorted(
        {g for g in exclusions.files if not any(_hit(exclusions, p, safe_resolve(p), (), (g,)) for p in named)}
    )
    return tuple(dirs), tuple(files)


def _hit(
    exclusions: RunExclusions, path: Path, resolved: Path, dirs: tuple[FolderValue, ...], files: tuple[str, ...]
) -> bool:
    """True when `path` (or its `resolved` form) falls under one of `dirs` or matches one of `files`."""
    if dirs and exclusions.folder_hit(exclusions.views(os.fspath(path), os.fspath(resolved)), dirs):
        return True
    if not files:
        return False
    return any(
        matches_any_glob(candidate, list(files), root)
        for candidate in dict.fromkeys((path, resolved))
        for root in exclusions.roots
    )


def load_run_exclusions(
    target: Path, flag_dirs: list[str] | None = None, flag_files: list[str] | None = None
) -> RunExclusions:
    """The run's exclusions at `target`: command-line patterns joined with the project's config."""
    config = get_project_config(target)
    return parse_run_exclusions(
        target, (*(flag_dirs or ()), *config.exclude_dirs), (*(flag_files or ()), *config.exclude_files)
    )
