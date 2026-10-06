"""Which agent a project's files point at: the clues that detect an agent.

A clue is a declared pattern that traces to one agent: a path in the agent's own folder
(`.claude/skills/**`, `.github/copilot-instructions.md`) or a root file name that is not one
the shared standard lists as shared (`CLAUDE.md`, `GEMINI.md`, `.cursorrules`). A shared name
(`AGENTS.md`) and a path in an editor folder (`.vscode/settings.json`) point at none of them.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.discovery import plugin_roots as _plugin_roots
from reporails_cli.core.discovery.walk import list_dir

if TYPE_CHECKING:
    from reporails_cli.core.discovery.agents import AgentType

logger = logging.getLogger(__name__)


def dir_prefix_from_glob(pattern: str) -> tuple[str, str] | None:
    """Extract (label, dir_path) from a glob pattern like '.cursor/rules/**/*.mdc'."""
    parts = Path(pattern).parts
    dir_parts = []
    for part in parts:
        if "*" in part:
            break
        dir_parts.append(part)
    if not dir_parts:
        return None
    return dir_parts[-1], Path(*dir_parts).as_posix()


def clue_patterns(agent_type: AgentType, registry: dict[str, AgentType]) -> list[str]:
    """The declared patterns whose presence in a project points at this agent and no other.

    The core agent is the default, so every pattern it declares counts. For any other agent
    a pattern counts when it sits in the agent's own `home_dir`, or is a root file name the
    core agent does not list in its `shared_names`, or is a rule path no other agent declares
    (`.agents/rules/*.md` is Antigravity's alone, while `.agents/skills/**` is read by several).
    """
    patterns = (*agent_type.instruction_patterns, *agent_type.rule_patterns)
    if agent_type.core:
        return list(patterns)
    shared = {name.lower() for other in registry.values() if other.core for name in other.shared_names}
    claimed_elsewhere = {
        _bare(p)
        for other in registry.values()
        if other.id != agent_type.id
        for p in (*other.instruction_patterns, *other.rule_patterns, *other.config_patterns)
    }
    own_rules = set(agent_type.rule_patterns)
    clues: list[str] = []
    for pattern in patterns:
        first, has_dir, _ = pattern.partition("/")
        own_rule = has_dir and pattern in own_rules and _bare(pattern) not in claimed_elsewhere
        if (has_dir and first == agent_type.home_dir) or (not has_dir and pattern.lower() not in shared) or own_rule:
            clues.append(pattern)
    return clues


def _bare(pattern: str) -> str:
    """A pattern without its any-depth prefix, so `**/.agents/rules/*.md` and `.agents/rules/*.md` compare equal."""
    return pattern.lstrip("*/")


def scan_marker_at(target: Path, agent_type: AgentType, registry: dict[str, AgentType]) -> bool:
    """Check whether a clue to this agent exists at exactly this directory level.

    Root-level files match case-INSENSITIVELY (`claude.md` == `CLAUDE.md`):
    repos in the wild use both conventions and the agent specs do not mandate
    exact case (the AGENTS.md spec is silent on casing). A pattern with a glob
    (`.claude/skills/**/*.md`) is a clue once its folder exists.
    """
    listed = list_dir(str(target))
    if listed is None:
        logger.warning("Cannot read %s to look for agent files", target)
    root_files_lower = {entry.name.lower() for entry in listed or () if entry.is_file or entry.is_symlink}

    for pattern in clue_patterns(agent_type, registry):
        if "*" in pattern:
            folder = dir_prefix_from_glob(pattern)
            if folder is not None and (target / folder[1]).is_dir():
                return True
        elif "/" in pattern:
            if os.path.lexists(target / pattern):
                return True
        elif pattern.lower() in root_files_lower:
            return True
    return False


def agent_has_marker(
    target: Path,
    agent_type: AgentType,
    registry: dict[str, AgentType],
    exclude_dirs: frozenset[str],
) -> bool:
    """Fast existence check — does this agent likely apply at target?

    Checks the target directory's own clues (files in ancestor directories are out of
    scope), then any plugin root the agent declares components for.
    """
    markers = _plugin_roots.plugin_markers(agent_type.instruction_patterns)
    return scan_marker_at(target, agent_type, registry) or any(
        _plugin_roots.find_plugin_roots(target, marker, exclude_dirs) for marker in markers
    )
