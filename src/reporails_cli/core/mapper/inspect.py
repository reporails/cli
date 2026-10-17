"""Per-file inspection — frontmatter parsing and agent-registry matching.

Surface for the mapper orchestration spine: given a Path on disk, produce the
metadata fields the wire format needs (loading scope, glob set, agent
attribution, frontmatter description). Pure I/O + pattern matching; no atom
processing, no ML, no caching state.

The registry-pattern match (`_find_best_registry_match`) pulls the agent-config
pattern/property accessors from `core/discovery`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from reporails_cli.core.discovery.agent_config import extract_patterns, extract_properties
from reporails_cli.core.discovery.agent_discovery import is_eager_global, is_memory_recall_entry, is_nested
from reporails_cli.core.discovery.plugin_roots import matches_plugin_pattern, split_plugin_pattern
from reporails_cli.core.platform.config.config import get_rules_path, iter_agent_configs
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_object, pattern_list
from reporails_cli.core.platform.utils.utils import config_pattern_matches, read_frontmatter_file

logger = logging.getLogger(__name__)


def _frontmatter_data(path: Path, *, lenient: bool = False) -> JsonObject:
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


def _load_registry() -> dict[str, JsonObject]:
    """Load all agent registry configs. Returns {agent: config_dict}."""
    registry_dir = get_rules_path()
    if not registry_dir.is_dir():
        return {}
    return {agent: data for _, data in iter_agent_configs(registry_dir) if isinstance(agent := data.get("agent"), str)}


_ACTIVATION_KEYS = (
    "loading",
    "precedence",
    "activation",
    "path_key",
    "always_key",
    "description_key",
    "trigger_key",
    "trigger_modes",
    "trigger_missing",
)


class _FileTypeSpec(NamedTuple):
    """A registry file type read for matching."""

    patterns: list[str]
    declared: dict[str, str | list[str]]  # the file type's own properties
    props: JsonObject  # `declared` with the activation keys folded in


def _read_file_type(ft: JsonValue) -> _FileTypeSpec:
    """A registry file type's patterns and properties (its activation keys folded in)."""
    if not isinstance(ft, dict):
        return _FileTypeSpec([], {}, {})
    declared = extract_properties(ft)
    props: JsonObject = {k: ([*v] if isinstance(v, list) else v) for k, v in declared.items()}
    for key in _ACTIVATION_KEYS:
        if key in ft:
            props[key] = ft[key]
    return _FileTypeSpec(extract_patterns(ft), declared, props)


def _scope_activation(ft: JsonValue, pattern: str) -> JsonObject:
    """The activation keys the location scope holding `pattern` declares; they override the file
    type's own (Copilot reads `paths`, not `applyTo`, in the `.claude/rules` scope)."""
    if not isinstance(ft, dict):
        return {}
    for scope_spec in as_object(ft.get("scopes")).values():
        if isinstance(scope_spec, dict) and pattern in pattern_list(scope_spec.get("patterns")):
            return {k: scope_spec[k] for k in _ACTIVATION_KEYS if k in scope_spec}
    return {}


def _match_lower(rel: str, pattern: str) -> bool:
    return config_pattern_matches(rel, pattern, ignore_case=True, anchor_loose_leaf=True)


def _plugin_match_specificity(patterns: list[str], path: Path | None, root: Path | None) -> int | None:
    """The best specificity among the plugin component patterns (`<marker>/...`) that match
    `path` from its plugin root, or None when none does (or there is no path to check)."""
    if path is None or root is None:
        return None
    specificities = [
        len(split[1].split("*")[0])
        for pat in patterns
        if (split := split_plugin_pattern(pat)) is not None and matches_plugin_pattern(path, root, pat, _match_lower)
    ]
    return max(specificities, default=None)


_Match = tuple[int, str, str, JsonObject]  # (specificity, agent, file type, properties)


def _beats(specificity: int, current: _Match | None) -> bool:
    """Whether a match of this specificity beats `current` (strictly more specific, or nothing held yet)."""
    return current is None or specificity > current[0]


def _outranks(
    specificity: int,
    agent_id: str,
    current: _Match | None,
    registry: dict[str, JsonObject],
) -> bool:
    """Whether a match beats `current`: more specific, or as specific and made by the core agent
    (the shared standard) -- a file name several agents declare (`AGENTS.md`) belongs to none of
    them, so the shared standard's owner takes it."""
    if current is None or specificity > current[0]:
        return True
    return specificity == current[0] and bool(registry[agent_id].get("core")) and not registry[current[1]].get("core")


@dataclass
class _RegistryQuery:
    """What one registry lookup is for: the file's lowered relative path, its absolute path and
    scan root when known, and the registry it is matched against."""

    rel_lower: str
    registry: dict[str, JsonObject]
    path: Path | None
    root: Path | None

    @property
    def below_root(self) -> bool:
        """Whether the file sits in a subdirectory rather than at the root."""
        return "/" in self.rel_lower and not self.rel_lower.startswith("/")


@dataclass
class _Picks:
    """The best match so far, and the best match for a subdirectory copy of an eager global file."""

    best: _Match | None = None
    below_root_copy: _Match | None = None


def _scan_file_type(query: _RegistryQuery, agent_id: str, type_name: str, ft: JsonValue, picks: _Picks) -> None:
    """Match one registry file type against the file, recording what it wins in `picks`."""
    patterns, declared, props = _read_file_type(ft)
    plugin_hit = _plugin_match_specificity(patterns, query.path, query.root)
    if plugin_hit is not None and _beats(plugin_hit, picks.best):
        picks.best = (plugin_hit, agent_id, type_name, props)
    for pat in patterns:
        if split_plugin_pattern(pat) is not None:
            continue
        pat_lower = pat.lower()
        if pat_lower.startswith("**/") and not query.below_root and is_nested(declared):
            continue
        if not config_pattern_matches(
            query.rel_lower,
            pat,
            full_path=query.path.as_posix() if query.path is not None else None,
            ignore_case=True,
            anchor_loose_leaf=True,
        ):
            continue
        specificity = len(pat_lower.split("*")[0])
        if pat_lower.startswith("**/") and query.below_root and is_eager_global(declared):
            if _outranks(specificity, agent_id, picks.below_root_copy, query.registry):
                picks.below_root_copy = (
                    specificity,
                    agent_id,
                    type_name,
                    {**props, "loading": "on_demand", "scope": "nested"},
                )
            continue
        if _outranks(specificity, agent_id, picks.best, query.registry):
            picks.best = (specificity, agent_id, type_name, {**props, **_scope_activation(ft, pat)})


def _find_best_registry_match(
    rel_lower: str,
    registry: dict[str, JsonObject],
    path: Path | None = None,
    root: Path | None = None,
) -> tuple[str, str, JsonObject] | None:
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
    query = _RegistryQuery(rel_lower, registry, path, root)
    picks = _Picks()
    for agent_id, config in registry.items():
        for type_name, ft in as_object(config.get("file_types")).items():
            _scan_file_type(query, agent_id, type_name, ft, picks)
    found = picks.best or picks.below_root_copy
    if found is None:
        return None
    return found[1], found[2], found[3]


def _frontmatter_text(path: Path, key: str) -> str:
    """The non-blank string under `key` in the file's frontmatter, else empty."""
    value = _frontmatter_data(path, lenient=True).get(key)
    return value.strip() if isinstance(value, str) else ""


def _trigger_activation(path: Path, props: JsonObject) -> tuple[str, str, tuple[str, ...]]:
    """Loading, scope and globs of a file whose frontmatter `trigger_key` picks its activation mode
    (Antigravity rules). A missing or unrecognised trigger takes the `trigger_missing` row."""
    modes = as_object(props.get("trigger_modes"))
    trigger = _frontmatter_text(path, str(props["trigger_key"])).lower()
    row = as_object(modes.get(trigger) or props.get("trigger_missing"))
    loading = str(row.get("loading", "on_demand"))
    scope = str(row.get("scope", "global"))
    if scope == "path_scoped":
        globs = _parse_frontmatter_globs(path, str(props.get("path_key", "globs")))
        if not globs:
            return loading, "global", ()
        return loading, scope, globs
    return loading, scope, ()


def _resolve_activation(path: Path, props: JsonObject, loading: str, scope: str) -> tuple[str, str, tuple[str, ...]]:
    """The loading, scope and globs a file's frontmatter gives it, from the activation keys its
    file type (or location scope) declares.

    `trigger_key` picks the mode from a declared table. Otherwise `always_key` true loads at session
    start; a non-empty `path_key` filter makes it path scoped; with no filter, a `description_key`
    value lets the agent pick the file by description (`on_invocation`), and a declared `always_key`
    or `description_key` without either leaves it for manual attachment (`on_demand`). A path-filtered
    type declaring none of those loads at session start without its filter. A nested file is scoped by
    where it lives, never by frontmatter.
    """
    if scope == "nested" or loading not in ("on_demand", "on_invocation"):
        return loading, scope, ()
    always_key = props.get("always_key")
    if loading == "on_demand" and props.get("trigger_key"):
        return _trigger_activation(path, props)
    if always_key and loading == "on_demand" and _frontmatter_flag(path, str(always_key)):
        return "session_start", "global", ()
    globs = _parse_frontmatter_globs(path, str(props.get("path_key", "globs")))
    if globs or loading == "on_invocation":
        return loading, scope, globs
    description_key = props.get("description_key")
    if description_key and _frontmatter_text(path, str(description_key)):
        return "on_invocation", "global", ()
    return ("on_demand" if always_key or description_key else "session_start"), "global", ()


# File types whose body loads when the agent or the user invokes them.
INVOKED_TYPES = frozenset(
    {"skills", "agents", "commands", "prompts", "output_styles", "scheduled_tasks", "skill_metadata"}
)


def activation_code(loading: str, scope: str, globs: tuple[str, ...], file_type: str, configured: str = "") -> str:
    """The agent-neutral way a file comes into context, from its resolved loading, scope, globs
    and type: always, subtree, launch_subtree, file_match, invoked, agent_decides or manual. A
    nested file takes the `activation` its file type's config row declares (`subtree` otherwise)."""
    if scope == "nested":
        return configured or "subtree"
    if loading == "session_start":
        return "always"
    if globs or scope == "path_scoped":
        return "file_match"
    if loading == "on_invocation":
        return "invoked" if file_type in INVOKED_TYPES else "agent_decides"
    return "manual"


def _detect_file_activation(
    path: Path,
    root: Path,
    registry: dict[str, JsonObject],
) -> tuple[str, str, tuple[str, ...], str, str, str]:
    """Determine loading/scope/globs/agent/type/activation for an instruction file.

    Matches the file against all agent registry patterns.
    Falls back to session_start/global/generic/generic if no match. The path filter is
    read from the frontmatter key the matched file type declares as `path_key`
    (`globs` when it declares none).

    Returns:
        (loading, scope, globs, agent, type, activation) — `type` is the matched file type's
        config key
    """
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    match = _find_best_registry_match(rel.lower(), registry, path, root)
    if match is None:
        return "session_start", "global", (), "generic", "generic", "always"

    agent_id, file_type, props = match
    loading = str(props.get("loading", "session_start"))
    scope = str(props.get("scope", "global"))
    loading, scope, globs = _resolve_activation(path, props, loading, scope)
    # Per-entry memory loading: only MEMORY.md is the eager index; sibling
    # entries are recalled on-demand — same rule the classifier stamps.
    if is_memory_recall_entry(file_type, path.name):
        loading = "on_demand"
    activation = activation_code(loading, scope, globs, file_type, str(props.get("activation", "")))
    return loading, scope, globs, agent_id, file_type, activation


def file_type_of(path: Path, root: Path, registry: dict[str, JsonObject]) -> str:
    """The config key of the file type `path` matches, `generic` when it matches none."""
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    match = _find_best_registry_match(rel.lower(), registry, path, root)
    return match[1] if match is not None else "generic"


class FileRead(NamedTuple):
    """How an agent reads a file: its file type, when it loads and from which precedence scope."""

    file_type: str
    loading: str
    precedence: str


def file_read_by(agent_id: str, path: Path, root: Path, registry: dict[str, JsonObject]) -> FileRead | None:
    """The file type, loading and precedence `agent_id`'s own file types give `path`, None when none matches.

    Loading is the mapper's own (`_detect_file_activation`); precedence is the matched location scope's.
    """
    config = registry.get(agent_id)
    if config is None:
        return None
    own = {agent_id: config}
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
    match = _find_best_registry_match(rel.lower(), own, path, root)
    if match is None:
        return None
    loading, _, _, _, file_type, _ = _detect_file_activation(path, root, own)
    return FileRead(file_type, loading, str(match[2].get("precedence", "")))
