"""Project-root resolution for discovery — where a run's scan scope begins and ends.

A directory target is its own root. The agent config directory names come from the bundled agent
configs.
"""

from __future__ import annotations

import functools
from pathlib import Path

from reporails_cli.core.discovery.agent_config import bundled_file_types
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object, pattern_list
from reporails_cli.core.platform.utils.utils import home_folder, is_rooted_pattern


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


# What a folder holds when it is a project's root: a git repository, or reporails project config.
PROJECT_ROOT_MARKERS: tuple[str, ...] = (".git", ".ails")


def is_project_root(folder: Path) -> bool:
    """Whether `folder` is a project's root: it holds a `.git` or an `.ails` folder."""
    return folder.is_dir() and any((folder / marker).exists() for marker in PROJECT_ROOT_MARKERS)


@functools.lru_cache(maxsize=1)
def root_markers() -> tuple[frozenset[str], ...]:
    """Per supported agent: the dot-directories it declares surfaces in (`.claude/`, `.codex/`,
    `.cursor/`, `.gemini/`, `.github/`, `.agents/`, …).

    Derived from the bundled `framework/rules/*/config.yml` so the set covers every shipped agent and
    follows config rather than a hand-kept list. User-scope (`~/…`) and absolute managed patterns are
    dropped: they say nothing about the directory under test.
    """
    per_agent = (_config_dirs_from_file_types(file_types) for file_types in bundled_file_types())
    return tuple(dirs for dirs in per_agent if dirs)


def _repo_relative_pattern(pattern: str) -> str:
    """Strip a scope pattern to its repo-relative form, or `` for a non-repo one."""
    text = str(pattern)
    if is_rooted_pattern(text):
        return ""
    return text.removeprefix("**/")


def _config_dirs_from_file_types(file_types: JsonObject) -> frozenset[str]:
    """The config dir names one agent's `file_types` declare surfaces in."""
    dirs: set[str] = set()
    for ft in file_types.values():
        if not isinstance(ft, dict):
            continue
        for scope in as_object(ft.get("scopes")).values():
            for pattern in pattern_list(as_object(scope).get("patterns")):
                rel = _repo_relative_pattern(pattern)
                head = rel.split("/", 1)[0]
                if "/" in rel and head.startswith(".") and "*" not in head:
                    dirs.add(head)
    return frozenset(dirs)


def agent_dir_names() -> frozenset[str]:
    """Every dot-directory a shipped agent declares surfaces in (`.claude`, `.codex`, …)."""
    return frozenset().union(*root_markers())


def outermost_agent_dir(target: Path) -> Path | None:
    """The outermost agent config directory (`.claude`, `.codex`, …) that is or holds `target`, if any."""
    agent_dirs = agent_dir_names()
    start = target if target.is_dir() else target.parent
    return next((folder for folder in reversed((start, *start.parents)) if folder.name in agent_dirs), None)


def user_level_agent_dir(target: Path) -> Path | None:
    """The agent config directory directly in the user's home that holds `target`, if any.

    Only the outermost agent directory above the target counts, and only when its parent
    is the home directory. Returns `None` for every project-level file.
    """
    outermost = outermost_agent_dir(target)
    if outermost is None:
        return None
    home = home_folder()
    return outermost if home is not None and outermost.parent.resolve() == home else None
