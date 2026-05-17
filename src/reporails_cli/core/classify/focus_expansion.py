"""Focus-mode expansion for capability targeting.

When per-capability targeting points at a subagent
(`ails check agents rule-writer`), the subagent's effective instruction
set includes any skills the subagent preloads. This module reads the
subagent file's frontmatter and resolves declared skills to their
canonical paths, so focus mode renders the subagent and its preloaded
skills together.

The expansion is agent-aware: ``framework/capabilities_matrix.yml``
declares which agents have both ``subagents`` and ``skills``
capabilities, and the cross-agent `skills:` frontmatter convention is
shared across those agents (per the 2026-05-10
``ails-check-targeted-scope`` seed).
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from reporails_cli.core.classify.capability_paths import resolve_capability

logger = logging.getLogger(__name__)

_SKILL_PRELOAD_FRONTMATTER_KEY = "skills"


def expand_focus(
    focus_paths: set[Path],
    agent: str,
    project_root: Path,
) -> set[Path]:
    """Expand `focus_paths` to include preloaded skills for any subagent in the set.

    Reads each focus path's YAML frontmatter and looks for a `skills:`
    field listing skill names. Each declared skill is resolved through
    `resolve_capability(agent, "skills", name, project_root)` and added
    to the expanded set. Paths that aren't subagents (no `skills:`
    field, no frontmatter, or not a known agents file) pass through
    unchanged.
    """
    expanded: set[Path] = set(focus_paths)
    for path in focus_paths:
        for skill_name in _read_preloaded_skills(path):
            resolved = resolve_capability(agent, "skills", skill_name, project_root)
            if resolved is not None:
                expanded.add(resolved)
            else:
                logger.debug(
                    "expand_focus: skill %r declared in %s not resolved for agent %s",
                    skill_name,
                    path,
                    agent,
                )
    return expanded


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
    frontmatter = _extract_frontmatter(text)
    if frontmatter is None:
        return None
    try:
        data = yaml.safe_load(frontmatter) or {}
    except yaml.YAMLError as exc:
        logger.debug("expand_focus: bad frontmatter in %s: %s", path, exc)
        return None
    if not isinstance(data, dict):
        return None
    return data.get(key)


def _extract_frontmatter(text: str) -> str | None:
    """Return the YAML between the leading `---` fences, or None."""
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    return text[3:end].strip()
