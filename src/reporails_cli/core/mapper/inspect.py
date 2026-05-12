"""Per-file inspection — frontmatter parsing and agent-registry matching.

Surface for the mapper orchestration spine: given a Path on disk, produce the
metadata fields the wire format needs (loading scope, glob set, agent
attribution, frontmatter description). Pure I/O + pattern matching; no atom
processing, no ML, no caching state.

The registry-pattern match in `_find_best_registry_match` lazy-imports from
`core/discovery/agents` to pull the agent-config pattern/property accessors.
Dependency direction is one-way (`mapper.inspect` → `discovery.agents`); the
discovery subsystem does not import from mapper.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _extract_frontmatter_yaml(path: Path) -> str:
    """Read a file and return the raw YAML frontmatter block, or empty string."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    return text[3:end] if end != -1 else ""


def _parse_frontmatter_description(path: Path) -> str:
    """Extract name + description from YAML frontmatter.

    These fields are surfaced into the model's base context by all agents
    (Agent Skills standard) for skill/agent discoverability. The combined
    string is what competes for attention even when the file isn't invoked.
    """
    raw = _extract_frontmatter_yaml(path)
    if not raw:
        return ""
    try:
        import yaml

        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            return ""
        name = str(data.get("name", ""))
        desc = str(data.get("description", ""))
        return f"{name}: {desc}" if name and desc else (name or desc)
    except Exception:  # yaml.YAMLError; yaml imported in try scope
        return ""


def _parse_frontmatter_globs(path: Path) -> tuple[str, ...]:
    """Extract globs from YAML frontmatter of a rule/skill file."""
    raw = _extract_frontmatter_yaml(path)
    if not raw:
        return ()
    try:
        import yaml

        data = yaml.safe_load(raw)
        if not isinstance(data, dict) or "globs" not in data:
            return ()
        globs = data["globs"]
        if isinstance(globs, list):
            return tuple(str(g) for g in globs)
        if isinstance(globs, str):
            return (globs,)
    except Exception:  # yaml.YAMLError; yaml imported in try scope
        pass
    return ()


def _load_registry() -> dict[str, dict[str, Any]]:
    """Load all agent registry configs. Returns {agent: config_dict}."""
    try:
        from reporails_cli.core.platform.config.bootstrap import get_rules_path

        registry_dir = get_rules_path()
    except ImportError:
        registry_dir = Path(__file__).parent.parent / "data" / "registry"
    configs: dict[str, dict[str, Any]] = {}
    if not registry_dir.is_dir():
        return configs
    try:
        import yaml
    except ImportError:
        return configs
    for config_path in sorted(registry_dir.glob("*/config.yml")):
        try:
            data = yaml.safe_load(config_path.read_text())
            agent = data.get("agent", config_path.parent.name)
            configs[agent] = data
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("Failed to load agent config %s: %s", config_path, exc)
            continue
    return configs


def _find_best_registry_match(
    rel_lower: str,
    registry: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]] | None:
    """Find the most specific registry pattern match for a file path.

    Returns (agent_id, properties) or None if no match.
    """
    import fnmatch

    from reporails_cli.core.discovery.agents import _extract_patterns, _extract_properties

    best: tuple[int, str, dict[str, Any]] | None = None  # (specificity, agent, props)

    for agent_id, config in registry.items():
        for ft in (config.get("file_types") or {}).values():
            patterns = _extract_patterns(ft) if isinstance(ft, dict) else []
            props = ft.get("properties", {}) if isinstance(ft, dict) else {}
            if not props:
                props = _extract_properties(ft) if isinstance(ft, dict) else {}
            for pat in patterns:
                pat_lower = pat.lower()
                candidates = [pat_lower]
                if "**/" in pat_lower:
                    candidates.append(pat_lower.replace("**/", ""))
                    candidates.append(pat_lower.replace("**/", "*/"))
                if any(fnmatch.fnmatch(rel_lower, c) for c in candidates):
                    specificity = len(pat_lower.split("*")[0])
                    if best is None or specificity > best[0]:
                        best = (specificity, agent_id, props)

    if best is None:
        return None
    return best[1], best[2]


def _detect_file_loading(
    path: Path,
    root: Path,
    registry: dict[str, dict[str, Any]],
) -> tuple[str, str, tuple[str, ...], str]:
    """Determine loading/scope/globs/agent for an instruction file.

    Matches the file against all agent registry patterns.
    Falls back to session_start/global/generic if no match.

    Returns:
        (loading, scope, globs, agent)
    """
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    match = _find_best_registry_match(rel.lower(), registry)
    if match is None:
        return "session_start", "global", (), "generic"

    agent_id, props = match
    loading = props.get("loading", "session_start")
    scope = props.get("scope", "global")
    globs: tuple[str, ...] = ()
    if loading in ("on_demand", "on_invocation"):
        globs = _parse_frontmatter_globs(path)
    if loading == "on_demand" and not globs:
        loading = "session_start"
        scope = "global"
    return loading, scope, globs, agent_id
