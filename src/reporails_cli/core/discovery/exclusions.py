"""The exclusion set of one run: the folders and file globs the user left out, and the built-in defaults."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, replace
from functools import cached_property
from pathlib import Path

from reporails_cli.core.discovery.walk import child_real, safe_resolve
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.policy.exclusion import FolderValue, parse_folder_value
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
    `prunes` is what directory walks ask: it adds the built-in defaults to the user's folders.
    `named` holds the resolved files the user named; they are never left out.
    """

    root: Path
    dirs: tuple[FolderValue, ...] = ()
    files: tuple[str, ...] = ()
    named: frozenset[Path] = frozenset()

    @classmethod
    def none(cls, root: Path) -> RunExclusions:
        """No user exclusions; walks still prune the built-in defaults."""
        return cls(root=root)

    @classmethod
    def parse(cls, root: Path, dirs: Iterable[str], files: Iterable[str]) -> RunExclusions:
        """The exclusions of the folder values `dirs` and file globs `files`, without repeats, in the order given."""
        roots = (root, safe_resolve(root))
        folders = dict.fromkeys(v for v in (parse_folder_value(d, roots) for d in dirs) if v is not None)
        return cls(root=root, dirs=tuple(folders), files=tuple(dict.fromkeys(files)))

    def with_named(self, paths: Iterable[Path]) -> RunExclusions:
        """A copy that also treats `paths` as named by the user."""
        return replace(self, named=self.named | {safe_resolve(p) for p in paths})

    @cached_property
    def _roots(self) -> tuple[Path, ...]:
        """The root as given and, when different, resolved."""
        resolved = safe_resolve(self.root)
        return (self.root,) if resolved == self.root else (self.root, resolved)

    @cached_property
    def _prefixes(self) -> tuple[str, ...]:
        """The root as given and resolved, each as a string ending in a separator."""
        return tuple(dict.fromkeys(os.fspath(root).rstrip(os.sep) + os.sep for root in self._roots))

    @cached_property
    def _named_homes(self) -> frozenset[str]:
        """Every named file and every folder above one."""
        return frozenset(str(item) for path in self.named for item in (path, *path.parents))

    def _views(self, path: str, real: str) -> tuple[str, ...]:
        """The root-relative posix forms of `path` (as given) and `real` (canonical) that a folder rule is tested on.

        Each is tried against the root as given and resolved. A form outside both roots, and the
        root itself, give nothing.
        """
        views: dict[str, None] = {}
        for form in (path,) if real == path else (path, real):
            for prefix in self._prefixes:
                if form.startswith(prefix) and len(form) > len(prefix):
                    rel = form[len(prefix) :]
                    views[rel if os.sep == "/" else rel.replace(os.sep, "/")] = None
        return tuple(views)

    @staticmethod
    def _folder_hit(views: tuple[str, ...], dirs: tuple[FolderValue, ...]) -> bool:
        """True when a folder rule in `dirs` leaves out any of the root-relative `views`."""
        return any(d.holds(view) for d in dirs for view in views)

    @staticmethod
    def _default_pruned(name: str) -> bool:
        """True when the listed folder `name` is a built-in default."""
        return name in DEFAULT_EXCLUDE_DIRS

    def _user_pruned(self, path: str, real: str) -> bool:
        """True when a user folder rule holds the folder `path` (canonical `real`) and it holds no named file."""
        if not self.dirs or not self._folder_hit(self._views(path, real), self.dirs):
            return False
        return not (self.named and (path in self._named_homes or real in self._named_homes))

    def prunes(self, path: str, name: str, real: str) -> bool:
        """True when a walk skips the listed folder `path` named `name` (`real` is its canonical path).

        The built-in defaults are skipped by name. A folder the user left out is skipped too, unless
        it holds a file the user named.
        """
        return self._default_pruned(name) or self._user_pruned(path, real)

    def covers(self, path: Path) -> bool:
        """True when a walk never reaches `path`: it, or a folder above it below the root, is skipped.

        Tests each segment from the root down for a built-in default, then for a user folder. A
        file at the end of `path` is listed by a walk, not skipped like a folder.
        """
        for root in self._roots:
            if path.is_relative_to(root):
                parts = path.relative_to(root).parts
                folder = os.fspath(root)
                real = os.fspath(self._roots[-1])
                for depth, part in enumerate(parts, 1):
                    folder = os.path.join(folder, part)
                    pruned = self._default_pruned(part)
                    if not pruned and self.dirs:
                        real = child_real(folder, part, real, os.path.islink(folder))
                        pruned = self._user_pruned(folder, real)
                    if pruned:
                        return depth < len(parts) or not os.path.isfile(folder)
                return False
        return False

    def leaves_out(self, path: Path) -> bool:
        """True when `path` sits in a folder the user left out or matches a file glob the user left out.

        A folder name is matched at any depth; a folder path is relative to the root. A named path is
        never left out. Built-in defaults never count. The path is tried as given and resolved,
        against the root as given and resolved.
        """
        if not self.dirs and not self.files:
            return False
        resolved = safe_resolve(path)
        if self.named and resolved in self.named:
            return False
        return self._hit(path, resolved, self.dirs, self.files)

    def record(self, *, narrowed: bool = False) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """The `(folders, file globs)` to report: every user pattern, sorted, without repeats.

        With `narrowed` (the run covers only the named files) a pattern that a named file matches is
        dropped; a pattern that matches nothing stays.
        """
        named = self.named if narrowed else frozenset()
        dirs = sorted({d.text for d in self.dirs if not any(self._dir_matches(p, d) for p in named)})
        files = sorted({g for g in self.files if not any(self._glob_matches(p, g) for p in named)})
        return tuple(dirs), tuple(files)

    def _dir_matches(self, path: Path, folder: FolderValue) -> bool:
        return self._hit(path, safe_resolve(path), (folder,), ())

    def _glob_matches(self, path: Path, glob: str) -> bool:
        return self._hit(path, safe_resolve(path), (), (glob,))

    def _hit(self, path: Path, resolved: Path, dirs: tuple[FolderValue, ...], files: tuple[str, ...]) -> bool:
        """True when `path` (or its `resolved` form) falls under one of `dirs` or matches one of `files`."""
        if dirs and self._folder_hit(self._views(os.fspath(path), os.fspath(resolved)), dirs):
            return True
        if not files:
            return False
        return any(
            matches_any_glob(candidate, list(files), root)
            for candidate in dict.fromkeys((path, resolved))
            for root in self._roots
        )


def load_run_exclusions(
    target: Path, flag_dirs: list[str] | None = None, flag_files: list[str] | None = None
) -> RunExclusions:
    """The run's exclusions at `target`: command-line patterns joined with the project's config."""
    config = get_project_config(target)
    return RunExclusions.parse(
        target, (*(flag_dirs or ()), *config.exclude_dirs), (*(flag_files or ()), *config.exclude_files)
    )
