"""Focus-mode expansion for capability targeting.

When per-capability targeting points at a subagent
(`ails check agents rule-writer`), the subagent's effective instruction
set includes any skills the subagent preloads. This module reads the
subagent file's frontmatter and resolves declared skills to their
canonical paths, so focus mode renders the subagent and its preloaded
skills together.

The expansion is agent-aware: ``framework/capabilities_matrix.yml``
declares which agents have both ``agents`` and ``skills``
capabilities, and the cross-agent `skills:` frontmatter convention is
shared across those agents.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.classify.capability_paths import (
    TargetError,
    available_capabilities,
    capability_declared,
    list_capability_targets,
    resolve_capability,
)
from reporails_cli.core.discovery.exclusions import load_run_exclusions
from reporails_cli.core.platform.utils.utils import read_frontmatter

if TYPE_CHECKING:
    from reporails_cli.core.discovery.exclusions import RunExclusions

logger = logging.getLogger(__name__)

_SKILL_PRELOAD_FRONTMATTER_KEY = "skills"


@dataclass(frozen=True)
class UnresolvedSkill:
    """A skill name declared by an agent that discovery could not resolve."""

    declared_in: Path
    skill_name: str
    agent: str


def expand_focus(
    focus_paths: set[Path],
    agent: str,
    project_root: Path,
    exclusions: RunExclusions | None = None,
) -> tuple[set[Path], list[UnresolvedSkill]]:
    """Expand `focus_paths` to include preloaded skills for any subagent in the set.

    Reads each focus path's YAML frontmatter and looks for a `skills:`
    field listing skill names. Each declared skill is resolved through
    `resolve_capability(agent, "skills", name, project_root)` and added
    to the expanded set, unless the run's `exclusions` (`None` reads the project's config)
    leave that skill out: it is neither checked nor reported unresolved. Paths that aren't subagents (no `skills:`
    field, no frontmatter, or not a known agents file) pass through
    unchanged.

    Returns the expanded path set plus a list of `UnresolvedSkill`
    records for declared names that did not resolve — caller surfaces
    them so silent drops do not mask missing-symlink misconfigurations.
    """
    exclusions = exclusions if exclusions is not None else load_run_exclusions(project_root)
    expanded: set[Path] = set(focus_paths)
    unresolved: list[UnresolvedSkill] = []
    for path in focus_paths:
        for skill_name in _read_preloaded_skills(path):
            resolved = resolve_capability(agent, "skills", skill_name, project_root)
            if resolved is not None:
                if not exclusions.leaves_out(resolved):
                    expanded.add(resolved)
            else:
                unresolved.append(UnresolvedSkill(declared_in=path, skill_name=skill_name, agent=agent))
    return expanded, unresolved


def resolve_capability_spec(
    capability: str,
    name: str,
    agent: str,
    project_root: Path,
    exclusions: RunExclusions | None = None,
) -> tuple[set[Path], list[UnresolvedSkill]]:
    """Resolve one (capability, name) spec to its file set + the skills an agent preloads that
    did not resolve. An empty `name` targets every instance the run's `exclusions` keep; a named
    instance resolves whatever is excluded, and a named subagent brings the skills it preloads
    that the exclusions keep. Raises `TargetError` when the spec names no file."""
    if not capability_declared(capability, agent, project_root):
        raise TargetError(
            "undeclared",
            capability,
            agent,
            project_root,
            name=name,
            available=tuple(available_capabilities(agent, project_root)),
        )
    if not name:
        return set(list_capability_targets(agent, capability, project_root, exclusions)), []
    resolved = resolve_capability(agent, capability, name, project_root)
    if resolved is None:
        available = list_capability_targets(agent, capability, project_root, exclusions)
        raise TargetError(
            "unnamed", capability, agent, project_root, name=name, available=tuple(str(p) for p in available)
        )
    paths = {resolved}
    unresolved: list[UnresolvedSkill] = []
    if capability == "agents":
        paths, unresolved = expand_focus(paths, agent, project_root, exclusions)
    return paths, unresolved


def _read_preloaded_skills(path: Path) -> list[str]:
    """Return skill names declared in `path`'s YAML frontmatter `skills:` field.

    Returns [] for files without frontmatter, without a `skills:` field,
    or when the field is not a list of strings.
    """
    raw = _load_frontmatter_field(path, _SKILL_PRELOAD_FRONTMATTER_KEY)
    if isinstance(raw, list):
        return [str(item) for item in raw if isinstance(item, str)]
    if isinstance(raw, str):
        return [s.strip() for s in raw.split(",") if s.strip()]
    return []


def _load_frontmatter_field(path: Path, key: str) -> object:
    """Read `path`'s YAML frontmatter and return the value at `key`, or None."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("expand_focus: cannot read %s: %s", path, exc)
        return None
    read = read_frontmatter(text)
    if read.problem is not None:
        logger.debug("expand_focus: bad frontmatter in %s: %s", path, read.problem.message)
    data = read.data or {}
    return data.get(key)
