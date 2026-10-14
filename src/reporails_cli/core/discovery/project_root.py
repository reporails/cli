"""Project-root resolution for discovery — where a run's scan scope begins and ends.

A directory target is its own root; a bare file target walks up to the project marker that
encloses it. The agent config directory names the walk recognizes come from the bundled agent
configs.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.agent_config import bundled_file_types


def resolve_project_root(target: Path) -> Path:
    """Project root for discovery — the directory `ails check` was pointed at.

    Discovery never walks above this directory. Whoever runs `ails check`
    chooses the scope — `target` IS the project root, regardless of what
    `.git` / `.ails/backbone.yml` / IDE config dirs may exist above it.

    Files outside `target`'s subtree are out of scope. This bounds the scan
    strictly to what the user pointed at and avoids leaking files from a
    surrounding repo into a fixture/subdirectory check.
    """
    return target if target.is_dir() else target.parent


@functools.lru_cache(maxsize=1)
def root_markers() -> tuple[tuple[tuple[str, ...], frozenset[str]], ...]:
    """Per supported agent: `(main-instruction relative paths, config directory names)`.

    Derived from the bundled `framework/rules/*/config.yml` so the marker set covers
    every shipped agent and follows config rather than a hand-kept list: the `main`
    file_type's project-scope patterns (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
    `.github/copilot-instructions.md`, …) paired with the dot-directories that agent
    declares surfaces in (`.claude/`, `.codex/`, `.cursor/`, `.gemini/`, `.github/`,
    `.agents/`, …). User-scope (`~/…`) and absolute managed patterns are dropped —
    they say nothing about the directory under test.
    """
    markers: list[tuple[tuple[str, ...], frozenset[str]]] = []
    for file_types in bundled_file_types():
        mains, dirs = _markers_from_file_types(file_types)
        if mains and dirs:
            markers.append((tuple(sorted(mains)), frozenset(dirs)))
    return tuple(markers)


def _repo_relative_pattern(pattern: str) -> str:
    """Strip a scope pattern to its repo-relative form, or `` for a non-repo one."""
    text = str(pattern)
    if text.startswith(("~", "/")) or ":" in text.split("/", 1)[0]:
        return ""
    return text.removeprefix("**/")


def _markers_from_file_types(file_types: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Split one agent's `file_types` into its main-file names and its config dir names."""
    mains: set[str] = set()
    dirs: set[str] = set()
    for ft_name, ft in file_types.items():
        if not isinstance(ft, dict):
            continue
        for scope in (ft.get("scopes") or {}).values():
            for pattern in (scope or {}).get("patterns", []) or []:
                rel = _repo_relative_pattern(pattern)
                if not rel:
                    continue
                if ft_name == "main" and "*" not in rel:
                    mains.add(rel)
                head = rel.split("/", 1)[0]
                if "/" in rel and head.startswith(".") and "*" not in head:
                    dirs.add(head)
    return mains, dirs


def agent_dir_names() -> frozenset[str]:
    """Every dot-directory a shipped agent declares surfaces in (`.claude`, `.codex`, …)."""
    return frozenset().union(*(dirs for _, dirs in root_markers())) if root_markers() else frozenset()


# Marker directories a project-boundary walk-up recognizes for `resolve_project_root_for_file`.
_FILE_ROOT_MARKER_DIRS: frozenset[str] = frozenset({".vscode", ".idea", ".github"})


def resolve_project_root_for_file(target: Path) -> Path:
    """Project root for a bare FILE target with no invoking cwd to anchor on.

    `resolve_project_root` is right for `ails check <dir>` / `ails check` (no
    target): whoever ran the command chose the scope, and for the CLI's own
    single-FILE case the effective root is the invoking terminal's `cwd` (set in
    `main.py`), never `target.parent` — a human runs `ails check .claude/rules/x.md`
    FROM the project root, not from inside `.claude/rules/`. An MCP-style caller
    passes only the file path with no cwd to read, so `target.parent` under-roots a
    nested file: `.claude/rules/style.md` resolved at `.claude/rules` instead of the
    project root, which misclassifies the file's `loading`/`scope`
    (`core/mapper/inspect.py::_detect_file_loading`) and computes a cache identity
    (`core/cache/full_map_cache.py::compute_identity`) that never matches the CLI's
    same-file run, so the two surfaces never share a whole-map cache entry.

    Walks up from the file looking for a project marker — `.ails/backbone.yml`,
    `.git`, then an IDE/CI config directory — falling back to the file's own
    directory when the walk finds nothing, exactly like a human `cd`-ing to the
    project root before invoking the CLI would resolve.

    A weaker fallback sits below those: the parent of the OUTERMOST agent config
    directory (`.claude`, `.cursor`, `.codex`, ... — the names the agents declare)
    enclosing the file. Such a directory groups one agent's own files under one
    project, so a config file living inside it with no `.git` / `.ails` / IDE marker
    above (`.claude/settings.json` in a project that has never been git-initialized,
    say) still resolves one level up. Any other hidden folder is no boundary, and a
    hidden folder inside an agent directory does not end the walk early.

    An agent directory that sits directly in the user's home (`~/.claude`) is the
    user's own configuration, not a project: the file roots on that directory
    itself, so nothing else under the home directory is ever scanned.

    An IDE/CI folder in the home directory, or in a directory above it, is not a
    project marker: the file roots as if it were absent. `.ails/backbone.yml` and
    `.git` count wherever they are.
    """
    user_dir = user_level_agent_dir(target)
    if user_dir is not None:
        return user_dir
    current = target if target.is_dir() else target.parent
    start = current
    first_git: Path | None = None
    first_marker: Path | None = None
    outermost_agent_dir: Path | None = None
    agent_dirs = agent_dir_names()
    try:
        home: Path | None = Path.home().resolve()
    except (RuntimeError, OSError):
        home = None
    while current != current.parent:
        if (current / ".ails" / "backbone.yml").exists():
            return current
        if first_git is None and (current / ".git").exists():
            first_git = current
        # An editor/host folder in the home directory (or above it) is shared by every
        # project below, so it never decides one project's root.
        if first_marker is None and not (home is not None and (current == home or home.is_relative_to(current))):
            for marker in _FILE_ROOT_MARKER_DIRS:
                if (current / marker).is_dir():
                    first_marker = current
                    break
        if current.name in agent_dirs:
            outermost_agent_dir = current
        current = current.parent
    return first_git or first_marker or (outermost_agent_dir.parent if outermost_agent_dir else None) or start


def user_level_agent_dir(target: Path) -> Path | None:
    """The agent config directory directly in the user's home that holds `target`, if any.

    Only the outermost agent directory above the target counts, and only when its parent
    is the home directory. Returns `None` for every project-level file.
    """
    agent_dirs = agent_dir_names()
    start = target if target.is_dir() else target.parent
    outermost: Path | None = None
    for ancestor in (start, *start.parents):
        if ancestor.name in agent_dirs:
            outermost = ancestor
    if outermost is None:
        return None
    try:
        home = Path.home().resolve()
    except (RuntimeError, OSError):
        return None
    return outermost if outermost.parent.resolve() == home else None
