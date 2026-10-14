"""Project-config adjustments to an agent's surfaces — extra patterns and fallback filenames.

Reads `surfaces.<agent>.<file_type>.include` / `.exclude` and `agents.<agent>.fallback_filenames`
from the project's `.ails/config.yml`, and drops the fallback files an agent never loads.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.discovery.walk import list_dir

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.results import ProjectConfig

# File types a declared fallback filename is added to: `main` covers the directories
# from the project root down to the run's directory, `nested_context` the
# subdirectories below it (the same split a plain `AGENTS.md` uses).
_FALLBACK_FILE_TYPES = frozenset({"main", "nested_context"})

# Names an agent reads before it tries any fallback name in the same directory.
_PRIMARY_NAMES: dict[str, frozenset[str]] = {"codex": frozenset({"agents.override.md", "agents.md"})}


def _fallback_names(project_config: ProjectConfig | None, agent_id: str) -> list[str]:
    """The `agents.<agent>.fallback_filenames` entries of the project config."""
    agent_cfg = (getattr(project_config, "agents", {}) or {}).get(agent_id)
    fallbacks = agent_cfg.get("fallback_filenames", []) if isinstance(agent_cfg, dict) else []
    if not isinstance(fallbacks, list):
        return []
    return [name for name in fallbacks if isinstance(name, str)]


def _dir_has_primary(directory: Path, agent_id: str) -> bool:
    """Whether `directory` holds a file the agent reads before any fallback name."""
    primary = _PRIMARY_NAMES.get(agent_id, frozenset())
    return any(entry.name.lower() in primary for entry in list_dir(str(directory)) or ())


def drop_shadowed_fallbacks(
    found: list[Path], agent_id: str, file_type_name: str, project_config: ProjectConfig | None
) -> list[Path]:
    """`found` without the fallback files the agent skips.

    The agent tries its own names in each directory first and reads a fallback
    name only when none of them is there, so a fallback file beside an
    `AGENTS.md` (or `AGENTS.override.md`) is never loaded.
    """
    if file_type_name not in _FALLBACK_FILE_TYPES or agent_id not in _PRIMARY_NAMES:
        return found
    names = {n.lower() for n in _fallback_names(project_config, agent_id)} - _PRIMARY_NAMES[agent_id]
    if not names:
        return found
    return [p for p in found if p.name.lower() not in names or not _dir_has_primary(p.parent, agent_id)]


def surface_include_patterns(agent_id: str, file_type_name: str, project_config: ProjectConfig | None) -> list[str]:
    """Patterns to ADD to a file_type's declared list, sourced from project config.

    Reads `surfaces.<agent>.<file_type>.include` from `.ails/config.yml`.
    Special case: for `<agent>.main` and `<agent>.nested_context`, also injects
    `**/<filename>` for each entry in `agents.<agent>.fallback_filenames` so
    user-declared alternative instruction filenames (e.g., Codex
    `project_doc_fallback_filenames`) are found at the root, in the directories
    down to the run's directory and in subdirectories.
    """
    if project_config is None:
        return []
    extra: list[str] = []
    surfaces = getattr(project_config, "surfaces", {}) or {}
    surface_key = f"{agent_id}.{file_type_name}"
    surface_cfg = surfaces.get(surface_key, {})
    if isinstance(surface_cfg, dict):
        include = surface_cfg.get("include", [])
        if isinstance(include, list):
            extra.extend(str(p) for p in include)

    if file_type_name in _FALLBACK_FILE_TYPES:
        extra.extend(f"**/{name}" for name in _fallback_names(project_config, agent_id))
    return extra


def config_names_agent(agent_id: str, project_config: ProjectConfig | None) -> bool:
    """True when the project's own config declares `agents.<agent>.fallback_filenames`.

    Declaring alternative instruction filenames for an agent is the project saying which
    agent reads them, so that agent is detected even when its fallback files sit only in
    subfolders (or beside the agent's own main file, where they are skipped).
    """
    return bool(_fallback_names(project_config, agent_id))


def surface_exclude_patterns(agent_id: str, file_type_name: str, project_config: ProjectConfig | None) -> list[str]:
    """Glob patterns whose matches should be DROPPED from a surface's results."""
    if project_config is None:
        return []
    surfaces = getattr(project_config, "surfaces", {}) or {}
    surface_key = f"{agent_id}.{file_type_name}"
    surface_cfg = surfaces.get(surface_key, {})
    if not isinstance(surface_cfg, dict):
        return []
    exclude = surface_cfg.get("exclude", [])
    if not isinstance(exclude, list):
        return []
    return [str(p) for p in exclude]
