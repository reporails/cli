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

import json
import os
from collections.abc import Callable, Sequence
from pathlib import Path

from reporails_cli.core.discovery.walk import Pruner, child_real, list_dir
from reporails_cli.core.platform.config.bootstrap import claude_plugins_dir
from reporails_cli.core.platform.config.claude_settings import enabled_plugins
from reporails_cli.core.platform.contract.errors import InstalledPluginsUnreadableError
from reporails_cli.core.platform.contract.glob_pattern import escape_glob
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object, pattern_list
from reporails_cli.core.platform.dto.discovery import ListedEntry
from reporails_cli.core.platform.utils.utils import config_pattern_matches

PLUGIN_SCOPE = "plugin"

# How far below the scan root a plugin root may sit: the project root itself, a
# marketplace's `plugins/<name>/`, and a monorepo package a level or two deeper.
_MAX_ROOT_DEPTH = 4


def plugin_scope_patterns(scope_spec: JsonObject, key: str = "patterns") -> list[str]:
    """A `plugin` scope's patterns (under `key`) in `<marker>/pattern` form (empty without a marker)."""
    marker = scope_spec.get("root_marker")
    patterns = pattern_list(scope_spec.get(key, []))
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


def _searchable_real(entry: ListedEntry, skip: Pruner, parent_real: str) -> str | None:
    """The canonical path of a listed folder worth searching (not hidden, not a symlink, not pruned), else `None`."""
    if entry.name.startswith(".") or not entry.is_dir or entry.is_symlink:
        return None
    real = child_real(entry.path, entry.name, parent_real, False)
    return None if skip.prunes(entry.path, entry.name, real) else real


def find_plugin_roots(target: Path, marker: str, skip: Pruner) -> list[Path]:
    """Directories at or below `target` (up to a few levels) that hold `marker`.

    Hidden directories and ones `skip` prunes are not searched; `target` itself is always
    checked. Sorted, so the expansion order is stable.
    """
    root = target if target.is_dir() else target.parent
    found: list[Path] = []
    frontier = [(root, os.path.realpath(root))]
    for depth in range(_MAX_ROOT_DEPTH + 1):
        next_frontier: list[tuple[Path, str]] = []
        for directory, directory_real in frontier:
            if _holds_marker(directory, marker):
                found.append(directory)
            if depth == _MAX_ROOT_DEPTH:
                continue
            for entry in list_dir(str(directory)) or ():
                real = _searchable_real(entry, skip, directory_real)
                if real is not None:
                    next_frontier.append((Path(entry.path), real))
        frontier = next_frontier
    return sorted(found)


def expand_plugin_patterns(
    patterns: list[str],
    target: Path,
    skip: Pruner,
    roots_by_marker: dict[str, list[Path]] | None = None,
    installed: Sequence[Path] = (),
) -> list[str]:
    """Replace each `<marker>/pattern` with one pattern per plugin root: a root-relative one for each
    root found under `target`, an absolute one for each `installed` root outside it; other patterns
    pass through unchanged. No plugin root, no pattern. `roots_by_marker` carries the roots already
    found across calls for one scan."""
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
            roots_by_marker[marker] = find_plugin_roots(root, marker, skip)
        for plugin_root in [*roots_by_marker[marker], *(r for r in installed if r not in roots_by_marker[marker])]:
            if not plugin_root.is_relative_to(root):
                out.append(f"{escape_glob(plugin_root.as_posix())}/{rest}")
                continue
            prefix = plugin_root.relative_to(root).as_posix()
            out.append(rest if prefix == "." else f"{prefix}/{rest}")
    return out


def plugin_relative_path(path: Path, scan_root: Path, marker: str, installed: Sequence[Path] = ()) -> str | None:
    """`path` relative to the `installed` plugin root it sits in, else to the nearest directory holding
    `marker`, searched from the file's own directory up to `scan_root`; None when no such directory
    sits in between."""
    held = next((root for root in installed if path.is_relative_to(root)), None)
    if held is not None:
        return path.relative_to(held).as_posix()
    try:
        path.relative_to(scan_root)
    except ValueError:
        return None
    directory = path.parent
    while True:
        if _holds_marker(directory, marker):
            return path.relative_to(directory).as_posix()
        if directory in (scan_root, directory.parent):
            return None
        directory = directory.parent


def matches_plugin_pattern(
    path: Path, scan_root: Path, pattern: str, match: Callable[[str, str], bool], installed: Sequence[Path] = ()
) -> bool | None:
    """For a `<marker>/pattern`: whether `path` sits under a plugin root (one found from `scan_root` or an
    `installed` one) and its path from that root satisfies `match(relative_path, pattern)`. None for any
    other pattern, so the caller falls back to its own matching."""
    split = split_plugin_pattern(pattern)
    if split is None:
        return None
    marker, rest = split
    first = rest.split("/", 1)[0]
    if "*" not in first and first.lower() not in path.as_posix().lower():
        return False
    relative = plugin_relative_path(path, scan_root, marker, installed)
    return relative is not None and bool(match(relative, rest))


def config_pattern_hits(
    file_path: Path, rel: str, pattern: str, scan_root: Path, installed: Sequence[Path] = ()
) -> bool:
    """Whether a declared config pattern matches the file at `rel`; a plugin component pattern
    instead matches the file's path from the plugin root it sits under."""

    def match(subject: str, pat: str) -> bool:
        return config_pattern_matches(subject, pat, full_path=file_path.as_posix())

    plugin_hit = matches_plugin_pattern(file_path, scan_root, pattern, match, installed)
    return match(rel, pattern) if plugin_hit is None else plugin_hit


def entry_pattern(path: Path, root: Path, patterns: list[str], installed: Sequence[Path] = ()) -> str | None:
    """The first of `patterns` that `path` matches, anchored the way file-type `patterns` are; None when none does."""
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    return next((p for p in patterns if config_pattern_hits(path, rel, p, root, installed)), None)


def _install_records(registry: Path) -> dict[str, list[JsonObject]]:
    """Each plugin id's install records in Claude Code's `installed_plugins.json`; empty when the file is absent."""
    if not registry.is_file():
        return {}
    try:
        data = as_object(json.loads(registry.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise InstalledPluginsUnreadableError(f"{registry}: cannot be read as JSON ({exc})") from exc
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        raise InstalledPluginsUnreadableError(f"{registry}: no `plugins` object")
    records: dict[str, list[JsonObject]] = {}
    for plugin_id, installs in plugins.items():
        if not isinstance(installs, list) or not all(
            isinstance(i, dict) and isinstance(i.get("scope"), str) and isinstance(i.get("installPath"), str)
            for i in installs
        ):
            raise InstalledPluginsUnreadableError(
                f"{registry}: `{plugin_id}` is not a list of installs with a `scope` and an `installPath`"
            )
        records[plugin_id] = [as_object(i) for i in installs]
    return records


def _applies_to(install: JsonObject, root: Path) -> bool:
    """Whether an install reaches a session in `root`: one that names the project it was made in (`projectPath`)
    only for that project, any other always."""
    project = install.get("projectPath")
    return project is None or (isinstance(project, str) and Path(project) == root)


def _enabled_by_default(plugin_root: Path) -> bool:
    """A plugin's manifest `defaultEnabled` (true when the manifest is absent, unreadable or silent)."""
    try:
        manifest = as_object(json.loads((plugin_root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return True
    return manifest.get("defaultEnabled") is not False


def installed_plugin_roots(root: Path) -> list[tuple[str, Path]]:
    """`(plugin id, plugin root)` for each plugin installed for a session in `root` and enabled there, from
    Claude Code's `installed_plugins.json`; an install whose folder is gone is left out. A plugin no settings
    file names follows its manifest's `defaultEnabled`. A record that cannot be read raises
    `InstalledPluginsUnreadableError`."""
    records = _install_records(claude_plugins_dir() / "installed_plugins.json")
    switches = enabled_plugins(root)
    found: list[tuple[str, Path]] = []
    for plugin_id, installs in sorted(records.items()):
        install = next((i for i in installs if _applies_to(i, root)), None)
        if install is None:
            continue
        plugin_root = Path(str(install["installPath"]))
        if plugin_root.is_dir() and switches.get(plugin_id, _enabled_by_default(plugin_root)):
            found.append((plugin_id, plugin_root))
    return found
