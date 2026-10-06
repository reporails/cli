"""Per-file inspection — frontmatter parsing and agent-registry matching.

Surface for the mapper orchestration spine: given a Path on disk, produce the
metadata fields the wire format needs (loading scope, glob set, agent
attribution, frontmatter description). Pure I/O + pattern matching; no atom
processing, no ML, no caching state.

The registry-pattern match (`_find_best_registry_match`) lazy-imports from
`core/discovery/agents` to pull the agent-config pattern/property accessors.
Dependency direction is one-way (`mapper.inspect` → `discovery.agents`); the
discovery subsystem does not import from mapper.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.platform.utils.utils import config_pattern_matches, load_yaml_file, read_frontmatter_file

logger = logging.getLogger(__name__)


def _frontmatter_data(path: Path, *, lenient: bool = False) -> dict[str, Any]:
    """The mapping in a file's frontmatter block; empty when the file or a readable block is missing."""
    read = read_frontmatter_file(path, lenient=lenient)
    return (read.data if read is not None else None) or {}


def _parse_frontmatter_description(path: Path) -> str:
    """Extract name + description from YAML frontmatter.

    These fields are surfaced into the model's base context by all agents
    (Agent Skills standard) for skill/agent discoverability, even when the
    file isn't invoked.
    """
    data = _frontmatter_data(path)
    name = str(data.get("name", ""))
    desc = str(data.get("description", ""))
    return f"{name}: {desc}" if name and desc else (name or desc)


def split_top_level_commas(value: str) -> tuple[str, ...]:
    """Split a comma-separated pattern string, keeping commas inside `{a,b}` groups."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in value:
        if ch == "{":
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
        elif ch == "," and not depth:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    parts.append("".join(current))
    return tuple(p.strip() for p in parts if p.strip())


def _parse_frontmatter_globs(path: Path, key: str = "globs") -> tuple[str, ...]:
    """Extract the path filter under `key` from YAML frontmatter of a rule/skill file.

    The filter is a list, or one comma-separated string (Claude `paths`, Copilot
    `applyTo`, Cursor `globs`); commas inside `{a,b}` stay in their glob. A block
    that is not valid YAML (a colon inside a `description:` value, an unquoted
    leading `*` in `paths: **/*.ts`) is read again with every one-line
    `key: value` quoted. Empty items are dropped.
    """
    globs = _frontmatter_data(path, lenient=True).get(key)
    if isinstance(globs, list):
        return tuple(str(g).strip() for g in globs if g is not None and str(g).strip())
    if isinstance(globs, str):
        return split_top_level_commas(globs)
    return ()


def path_filter_key(path: Path, root: Path) -> str | None:
    """The frontmatter key the file's registry file type declares as its `path_key` (`globs` when it declares
    none); None for a file no file type claims."""
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    match = _find_best_registry_match(rel.lower(), _load_registry(), path, root)
    return str(match[2].get("path_key", "globs")) if match else None


def _frontmatter_flag(path: Path, key: str) -> bool:
    """True when the frontmatter value under `key` is boolean true."""
    return _frontmatter_data(path, lenient=True).get(key) is True


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
    for config_path in sorted(registry_dir.glob("*/config.yml")):
        try:
            data = load_yaml_file(config_path)
            agent = data.get("agent", config_path.parent.name)
            configs[agent] = data
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("Failed to load agent config %s: %s", config_path, exc)
            continue
    return configs


def _file_type_patterns_and_props(ft: Any) -> tuple[list[str], dict[str, Any]]:
    """A registry file type's patterns and properties (its `path_key` and `always_key` folded in)."""
    from reporails_cli.core.discovery.agents import _extract_patterns, _extract_properties

    if not isinstance(ft, dict):
        return [], {}
    props = ft.get("properties", {}) or _extract_properties(ft)
    for key in ("path_key", "always_key"):
        if key in ft:
            props = {**props, key: ft[key]}
    return _extract_patterns(ft), props


def _match_lower(rel: str, pattern: str) -> bool:
    return config_pattern_matches(rel, pattern, ignore_case=True, anchor_loose_leaf=True)


def _plugin_match_specificity(patterns: list[str], path: Path | None, root: Path | None) -> int | None:
    """The best specificity among the plugin component patterns (`<marker>/...`) that match
    `path` from its plugin root, or None when none does (or there is no path to check)."""
    from reporails_cli.core.discovery.plugin_roots import matches_plugin_pattern, split_plugin_pattern

    if path is None or root is None:
        return None
    best: int | None = None
    for pat in patterns:
        split = split_plugin_pattern(pat)
        if split is None or not matches_plugin_pattern(path, root, pat, _match_lower):
            continue
        specificity = len(split[1].split("*")[0])
        best = specificity if best is None else max(best, specificity)
    return best


def _outranks(
    specificity: int,
    agent_id: str,
    current: tuple[int, str, str, dict[str, Any]] | None,
    registry: dict[str, dict[str, Any]],
) -> bool:
    """Whether a match beats `current`: more specific, or as specific and made by the core agent
    (the shared standard) -- a file name several agents declare (`AGENTS.md`) belongs to none of
    them, so the shared standard's owner takes it."""
    if current is None or specificity > current[0]:
        return True
    return specificity == current[0] and bool(registry[agent_id].get("core")) and not registry[current[1]].get("core")


def _find_best_registry_match(
    rel_lower: str,
    registry: dict[str, dict[str, Any]],
    path: Path | None = None,
    root: Path | None = None,
) -> tuple[str, str, dict[str, Any]] | None:
    """Find the most specific registry pattern match for a file path.

    A `**/<leaf>` pattern names the file at the root (or above it) under a file type that
    loads at session start with global scope, and the copies in subdirectories under a
    `scope: nested` type, so a root `CLAUDE.md` and a `tests/CLAUDE.md` resolve to
    different file types. A subdirectory copy of a leaf whose agent declares no nested
    type keeps that agent's match and loads when work touches its subdirectory. A plugin
    component pattern (`<marker>/skills/**/SKILL.md`) matches the file's path from the
    plugin root holding the marker, so it needs `path` and `root`.

    Returns (agent_id, file_type, properties) or None if no match; `file_type` is the matched
    type's key in the agent's config.
    """
    from reporails_cli.core.discovery.agent_discovery import _is_eager_global, _is_nested
    from reporails_cli.core.discovery.plugin_roots import split_plugin_pattern

    below_root = "/" in rel_lower and not rel_lower.startswith("/")

    best: tuple[int, str, str, dict[str, Any]] | None = None  # (specificity, agent, type, props)
    below_root_copy: tuple[int, str, str, dict[str, Any]] | None = None

    for agent_id, config in registry.items():
        for type_name, ft in (config.get("file_types") or {}).items():
            patterns, props = _file_type_patterns_and_props(ft)
            plugin_hit = _plugin_match_specificity(patterns, path, root)
            if plugin_hit is not None and (best is None or plugin_hit > best[0]):
                best = (plugin_hit, agent_id, type_name, props)
            for pat in patterns:
                if split_plugin_pattern(pat) is not None:
                    continue
                pat_lower = pat.lower()
                if pat_lower.startswith("**/") and not below_root and _is_nested(props):
                    continue
                if not config_pattern_matches(
                    rel_lower,
                    pat,
                    full_path=path.as_posix() if path is not None else None,
                    ignore_case=True,
                    anchor_loose_leaf=True,
                ):
                    continue
                specificity = len(pat_lower.split("*")[0])
                if pat_lower.startswith("**/") and below_root and _is_eager_global(props):
                    if _outranks(specificity, agent_id, below_root_copy, registry):
                        below_root_copy = (
                            specificity,
                            agent_id,
                            type_name,
                            {**props, "loading": "on_demand", "scope": "nested"},
                        )
                    continue
                if _outranks(specificity, agent_id, best, registry):
                    best = (specificity, agent_id, type_name, props)

    found = best or below_root_copy
    if found is None:
        return None
    return found[1], found[2], found[3]


def _detect_file_loading(
    path: Path,
    root: Path,
    registry: dict[str, dict[str, Any]],
) -> tuple[str, str, tuple[str, ...], str, str]:
    """Determine loading/scope/globs/agent/type for an instruction file.

    Matches the file against all agent registry patterns.
    Falls back to session_start/global/generic/generic if no match. The path filter is
    read from the frontmatter key the matched file type declares as `path_key`
    (`globs` when it declares none).

    Returns:
        (loading, scope, globs, agent, type) — `type` is the matched file type's config key
    """
    from reporails_cli.core.discovery.agent_discovery import is_memory_recall_entry

    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    match = _find_best_registry_match(rel.lower(), registry, path, root)
    if match is None:
        return "session_start", "global", (), "generic", "generic"

    agent_id, file_type, props = match
    loading = props.get("loading", "session_start")
    scope = props.get("scope", "global")
    globs: tuple[str, ...] = ()
    # A file type that declares an `always_key` (Cursor rules: `alwaysApply`) loads at session
    # start whenever that key is true, whatever path filter the file also carries; without it
    # the agent or the user pulls the file in on demand.
    always_key = props.get("always_key")
    always = (
        bool(always_key) and loading == "on_demand" and scope != "nested" and _frontmatter_flag(path, str(always_key))
    )
    if always:
        loading, scope = "session_start", "global"
    elif loading in ("on_demand", "on_invocation"):
        globs = _parse_frontmatter_globs(path, str(props.get("path_key", "globs")))
    # A path-filtered file type (`.claude/rules`) without its filter loads at session start;
    # a nested file is scoped by where it lives, never by frontmatter. A file type with an
    # `always_key` that is not true stays on demand.
    if loading == "on_demand" and not globs and scope != "nested":
        if not always_key:
            loading = "session_start"
        scope = "global"
    # Per-entry memory loading: only MEMORY.md is the eager index; sibling
    # entries are recalled on-demand — same rule the classifier stamps.
    if is_memory_recall_entry(file_type, path.name):
        loading = "on_demand"
    return loading, scope, globs, agent_id, file_type


def file_type_of(path: Path, root: Path, registry: dict[str, dict[str, Any]]) -> str:
    """The config key of the file type `path` matches, `generic` when it matches none."""
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    match = _find_best_registry_match(rel.lower(), registry, path, root)
    return match[1] if match is not None else "generic"
