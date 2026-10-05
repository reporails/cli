"""Plugin roots: directories whose components an agent loads relative to the root itself.

A Claude Code plugin is a directory holding `.claude-plugin/plugin.json`; its skills,
agents and commands sit at the plugin root (`skills/<name>/SKILL.md`, `agents/*.md`,
`commands/*.md`), not under `.claude/`. An agent config declares these components in a
file type's `plugin` scope, with patterns relative to the plugin root and the manifest
that marks a root under `root_marker`. `_extract_patterns` carries each one as
`<marker>/pattern`; the helpers here resolve that form against the directories that
really hold the marker, so a top-level `skills/` folder in a project with no plugin
manifest is never read as a plugin's skills.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.walk import ListedEntry, list_dir

PLUGIN_SCOPE = "plugin"

# How far below the scan root a plugin root may sit: the project root itself, a
# marketplace's `plugins/<name>/`, and a monorepo package a level or two deeper.
_MAX_ROOT_DEPTH = 4


def plugin_scope_patterns(scope_spec: dict[str, Any], key: str = "patterns") -> list[str]:
    """A `plugin` scope's patterns (under `key`) in `<marker>/pattern` form (empty without a marker)."""
    marker = scope_spec.get("root_marker")
    patterns = scope_spec.get(key, [])
    if isinstance(patterns, str):
        patterns = [patterns]
    if not isinstance(marker, str) or not marker:
        return []
    return [f"<{marker}>/{pattern}" for pattern in patterns]


def split_plugin_pattern(pattern: str) -> tuple[str, str] | None:
    """`(marker, pattern relative to the plugin root)` for a `<marker>/pattern`, else None."""
    if not pattern.startswith("<"):
        return None
    end = pattern.find(">/")
    if end < 2:
        return None
    return pattern[1:end], pattern[end + 2 :]


def plugin_markers(patterns: list[str] | tuple[str, ...]) -> set[str]:
    """Every marker named by a `<marker>/pattern` among `patterns`."""
    return {split[0] for p in patterns if (split := split_plugin_pattern(p)) is not None}


def _holds_marker(directory: Path, marker: str) -> bool:
    try:
        return (directory / marker).is_file()
    except OSError:  # a directory the user cannot read holds nothing we can check
        return False


def _is_searchable_dir(entry: ListedEntry, exclude_dirs: frozenset[str]) -> bool:
    if entry.name.startswith(".") or entry.name in exclude_dirs:
        return False
    return entry.is_dir and not entry.is_symlink


def find_plugin_roots(target: Path, marker: str, exclude_dirs: frozenset[str]) -> list[Path]:
    """Directories at or below `target` (up to a few levels) that hold `marker`.

    Hidden directories and excluded ones are not searched; `target` itself is always
    checked. Sorted, so the expansion order is stable.
    """
    root = target if target.is_dir() else target.parent
    found: list[Path] = []
    frontier = [root]
    for depth in range(_MAX_ROOT_DEPTH + 1):
        next_frontier: list[Path] = []
        for directory in frontier:
            if _holds_marker(directory, marker):
                found.append(directory)
            if depth == _MAX_ROOT_DEPTH:
                continue
            next_frontier.extend(
                Path(entry.path) for entry in list_dir(str(directory)) or () if _is_searchable_dir(entry, exclude_dirs)
            )
        frontier = next_frontier
    return sorted(found)


def expand_plugin_patterns(
    patterns: list[str],
    target: Path,
    exclude_dirs: frozenset[str],
    roots_by_marker: dict[str, list[Path]] | None = None,
) -> list[str]:
    """Replace each `<marker>/pattern` with one root-relative pattern per plugin root found
    under `target`; other patterns pass through unchanged. No plugin root, no pattern.
    `roots_by_marker` carries the roots already found across calls for one scan."""
    root = target if target.is_dir() else target.parent
    if roots_by_marker is None:
        roots_by_marker = {}
    out: list[str] = []
    for pattern in patterns:
        split = split_plugin_pattern(pattern)
        if split is None:
            out.append(pattern)
            continue
        marker, rest = split
        if marker not in roots_by_marker:
            roots_by_marker[marker] = find_plugin_roots(root, marker, exclude_dirs)
        for plugin_root in roots_by_marker[marker]:
            prefix = plugin_root.relative_to(root).as_posix()
            out.append(rest if prefix == "." else f"{prefix}/{rest}")
    return out


def plugin_relative_path(path: Path, scan_root: Path, marker: str) -> str | None:
    """`path` relative to the nearest directory holding `marker`, searched from the file's
    own directory up to `scan_root`; None when no such directory sits in between."""
    try:
        path.relative_to(scan_root)
    except ValueError:
        return None
    directory = path.parent
    while True:
        if _holds_marker(directory, marker):
            return path.relative_to(directory).as_posix()
        if directory == scan_root or directory == directory.parent:
            return None
        directory = directory.parent


def matches_plugin_pattern(path: Path, scan_root: Path, pattern: str, match: Any) -> bool | None:
    """For a `<marker>/pattern`: whether `path` sits under a plugin root and its path from
    that root satisfies `match(relative_path, pattern)`. None for any other pattern, so
    the caller falls back to its own matching."""
    split = split_plugin_pattern(pattern)
    if split is None:
        return None
    marker, rest = split
    first = rest.split("/", 1)[0]
    if "*" not in first and first.lower() not in path.as_posix().lower():
        return False
    relative = plugin_relative_path(path, scan_root, marker)
    return relative is not None and bool(match(relative, rest))
