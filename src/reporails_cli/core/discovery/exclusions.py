"""The exclusion set of one run: the folders and file globs the user left out, and the built-in defaults."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from functools import cached_property
from pathlib import Path

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.policy.exclusion import excluded_by_name
from reporails_cli.core.platform.utils.utils import matches_any_glob

DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        # VCS
        ".git",
        ".svn",
        ".hg",
        # Python
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        # JS/TS
        "node_modules",
        # Build output
        "dist",
        "build",
        "target",
        "out",
        # Data / artifacts (instruction files never live here)
        "data",
        "datasets",
        # Vendored
        "vendor",
        # IDE / OS
        ".idea",
        # `.vscode` is deliberately absent: Copilot declares real config/mcp
        # surfaces there (`.vscode/{settings,mcp}.json`), pre-filtered out otherwise.
    }
)


@dataclass(frozen=True)
class RunExclusions:
    """What a run leaves out.

    `dirs` and `files` are the user's folders and file globs (command line plus config).
    `walk_dirs` adds the built-in defaults and is what directory walks prune.
    `named` holds the resolved files the user named; they are never left out.
    """

    root: Path
    dirs: frozenset[str] = frozenset()
    files: tuple[str, ...] = ()
    walk_dirs: frozenset[str] = DEFAULT_EXCLUDE_DIRS
    named: frozenset[Path] = frozenset()

    @classmethod
    def none(cls, root: Path) -> RunExclusions:
        """No user exclusions; walks still prune the built-in defaults."""
        return cls(root=root)

    def with_named(self, paths: Iterable[Path]) -> RunExclusions:
        """A copy that also treats `paths` as named by the user."""
        return replace(self, named=self.named | {safe_resolve(p) for p in paths})

    @cached_property
    def _roots(self) -> tuple[Path, ...]:
        """The root as given and, when different, resolved."""
        resolved = safe_resolve(self.root)
        return (self.root,) if resolved == self.root else (self.root, resolved)

    @cached_property
    def feature_walk_dirs(self) -> frozenset[str]:
        """The built-in defaults plus the user's folder names that hold no named file."""
        return DEFAULT_EXCLUDE_DIRS | {
            d for d in self.dirs if "/" not in d and not any(self._dir_matches(p, d) for p in self.named)
        }

    def leaves_out(self, path: Path) -> bool:
        """True when `path` sits in a folder the user left out or matches a file glob the user left out.

        A folder value without `/` is a folder name matched at any depth; one with `/` is a folder
        relative to the root. A named path is never left out. Built-in defaults never count. The path
        is tried as given and resolved, against the root as given and resolved.
        """
        if not self.dirs and not self.files:
            return False
        resolved = safe_resolve(path)
        if self.named and resolved in self.named:
            return False
        return self._hit(path, resolved, tuple(self.dirs), self.files)

    def record(self, *, narrowed: bool = False) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """The `(folders, file globs)` to report: every user pattern, sorted, without repeats.

        With `narrowed` (the run covers only the named files) a pattern that a named file matches is
        dropped; a pattern that matches nothing stays.
        """
        named = self.named if narrowed else frozenset()
        dirs = sorted(d for d in self.dirs if not any(self._dir_matches(p, d) for p in named))
        files = sorted({g for g in self.files if not any(self._glob_matches(p, g) for p in named)})
        return tuple(dirs), tuple(files)

    def _dir_matches(self, path: Path, name: str) -> bool:
        return self._hit(path, safe_resolve(path), (name,), ())

    def _glob_matches(self, path: Path, glob: str) -> bool:
        return self._hit(path, safe_resolve(path), (), (glob,))

    def _hit(self, path: Path, resolved: Path, dirs: tuple[str, ...], files: tuple[str, ...]) -> bool:
        """True when `path` (or its `resolved` form) falls under one of `dirs` or matches one of `files`."""
        names = frozenset(d for d in dirs if "/" not in d)
        prefixes = [tuple(d.split("/")) for d in dirs if "/" in d]
        for candidate in (path,) if resolved == path else (path, resolved):
            for root in self._roots:
                try:
                    parts = candidate.relative_to(root).parts
                except ValueError:
                    parts = ()
                if names and excluded_by_name(parts, names):
                    return True
                if any(parts[: len(prefix)] == prefix for prefix in prefixes):
                    return True
                if files and matches_any_glob(candidate, list(files), root):
                    return True
        return False


def _normalized_dir(value: str) -> str:
    """A folder value without a leading `./` or trailing `/`; empty when nothing is left."""
    value = value.strip()
    while value.startswith("./"):
        value = value[2:]
    return value.rstrip("/")


def load_run_exclusions(
    target: Path, flag_dirs: list[str] | None = None, flag_files: list[str] | None = None
) -> RunExclusions:
    """The run's exclusions at `target`: command-line patterns joined with the project's config."""
    config = get_project_config(target)
    dirs = frozenset(d for d in map(_normalized_dir, (*(flag_dirs or ()), *config.exclude_dirs)) if d)
    files = tuple(dict.fromkeys((*(flag_files or ()), *config.exclude_files)))
    return RunExclusions(
        root=target, dirs=dirs, files=files, walk_dirs=DEFAULT_EXCLUDE_DIRS | {d for d in dirs if "/" not in d}
    )


def load_project_exclude_dirs(target: Path) -> frozenset[str]:
    """The built-in default excludes plus the project's `exclude_dirs`."""
    return load_run_exclusions(target).walk_dirs
