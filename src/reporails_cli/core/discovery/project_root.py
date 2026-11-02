"""Project-root resolution for discovery — where a run's scan scope begins and ends.

A directory target is its own root. The agent config directory names come from the bundled agent
configs.
"""

from __future__ import annotations

import functools
from pathlib import Path

from reporails_cli.core.discovery.agent_config import bundled_file_types
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object, pattern_list
from reporails_cli.core.platform.utils.utils import is_rooted_pattern


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


def home_folder() -> Path | None:
    """The user's home folder, resolved; None when it cannot be determined."""
    try:
        return Path.home().resolve()
    except (RuntimeError, OSError):
        return None


def git_root(start: Path) -> Path | None:
    """Nearest ancestor of `start` (itself included) with a `.git` entry, below home; None when none."""
    home = home_folder()
    for candidate in (start, *start.parents):
        # The home folder, or a folder above it, is never a project root.
        if home and (candidate == home or home.is_relative_to(candidate)):
            break
        if (candidate / ".git").exists():
            return candidate
    return None


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
    if is_rooted_pattern(text):
        return ""
    return text.removeprefix("**/")


def _markers_from_file_types(file_types: JsonObject) -> tuple[set[str], set[str]]:
    """Split one agent's `file_types` into its main-file names and its config dir names."""
    mains: set[str] = set()
    dirs: set[str] = set()
    for ft_name, ft in file_types.items():
        if not isinstance(ft, dict):
            continue
        for scope in as_object(ft.get("scopes")).values():
            for pattern in pattern_list(as_object(scope).get("patterns")):
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
    home = home_folder()
    return outermost if home is not None and outermost.parent.resolve() == home else None
