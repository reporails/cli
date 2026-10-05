"""Agent definitions - coding agent agnostic discovery.

File discovery is driven by agent config.yml (file_types section) bundled
in framework/rules/*/config.yml. The agent registry is built at first
access from these configs — no hardcoded agent list.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reporails_cli.core.discovery import plugin_roots as _plugin_roots
from reporails_cli.core.discovery.agent_discovery import _agent_namespace, is_excluded
from reporails_cli.core.discovery.agent_discovery import categorize_file_type as _categorize_file_type
from reporails_cli.core.discovery.agent_discovery import config_names_agent as _config_names_agent
from reporails_cli.core.discovery.agent_discovery import discover_from_config as _discover_from_config
from reporails_cli.core.discovery.agent_markers import agent_has_marker, dir_prefix_from_glob
from reporails_cli.core.discovery.file_aliases import _dedupe_with_aliases, _store_alias_cache, clear_alias_cache
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.utils.utils import matches_any_glob

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.results import ProjectConfig

logger = logging.getLogger(__name__)


def _extract_patterns(spec: dict[str, Any], key: str = "patterns") -> list[str]:
    """Extract all file patterns from a file type spec (`key` names the pattern list: `patterns`, or
    `entry_patterns` for where an instance's entry file sits).

    Supports both v0.3.0 (patterns at top level) and v0.5.0 (patterns
    inside scopes). Returns a flat list of all patterns across all scopes; a `plugin`
    scope's patterns come back as `<marker>/pattern` (see `plugin_roots`).
    """
    # v0.3.0: patterns at top level
    patterns = spec.get(key, [])
    if isinstance(patterns, str):
        patterns = [patterns]
    if patterns:
        return list(patterns)

    # v0.5.0: patterns inside scopes
    scopes = spec.get("scopes", {})
    if not isinstance(scopes, dict):
        return []
    all_patterns: list[str] = []
    for scope_name, scope_spec in scopes.items():
        if not isinstance(scope_spec, dict):
            continue
        if scope_name == _plugin_roots.PLUGIN_SCOPE:
            all_patterns.extend(_plugin_roots.plugin_scope_patterns(scope_spec, key))
            continue
        scope_patterns = scope_spec.get(key, [])
        if isinstance(scope_patterns, str):
            scope_patterns = [scope_patterns]
        all_patterns.extend(scope_patterns)
    return all_patterns


def _extract_properties(spec: dict[str, Any]) -> dict[str, Any]:
    """Extract properties from a file type spec.

    Supports both v0.3.0 (properties nested) and v0.5.0 (flattened).
    """
    # v0.3.0: properties in a nested dict
    props = spec.get("properties")
    if isinstance(props, dict):
        return props

    # v0.5.0: properties flattened at file type level
    prop_keys = {"format", "scope", "cardinality", "lifecycle", "maintainer", "vcs", "loading", "precedence"}
    return {k: v for k, v in spec.items() if k in prop_keys and v is not None}


@dataclass(frozen=True)
class AgentType:
    """Definition of a coding agent's file conventions."""

    id: str
    name: str
    instruction_patterns: tuple[str, ...]  # Root-level marker patterns for fast detection
    config_patterns: tuple[str, ...]  # Glob patterns for config files
    rule_patterns: tuple[str, ...]  # Glob patterns for rule/snippet files
    directory_patterns: tuple[tuple[str, str], ...] = ()  # (label, dir_path) pairs
    core: bool = False  # the shared standard every other agent also reads (the default agent)
    home_dir: str = ""  # the dot-folder holding the agent's own files (`.claude`)
    shared_names: tuple[str, ...] = ()  # root file names several agents read; each points at no one agent


def _parse_agent_config(data: dict[str, Any]) -> AgentType | None:
    """Parse a single agent config.yml into an AgentType."""
    agent_id = data.get("agent")
    agent_name: str = data.get("name", agent_id) or agent_id or ""
    file_types = data.get("file_types")
    if not agent_id or not file_types or not isinstance(file_types, dict):
        return None

    instr_patterns: list[str] = []
    cfg_patterns: list[str] = []
    rule_pats: list[str] = []
    dir_patterns: list[tuple[str, str]] = []

    for spec in file_types.values():
        if not isinstance(spec, dict):
            continue
        patterns = _extract_patterns(spec)
        properties = _extract_properties(spec)

        bucket = _categorize_file_type(patterns, properties)

        if bucket == "instruction":
            instr_patterns.extend(
                root_p for p in patterns if (root_p := p.lstrip("*").lstrip("/")) and not root_p.startswith(("/", "~"))
            )
        elif bucket == "rule":
            rule_pats.extend(patterns)
            for p in patterns:
                pair = dir_prefix_from_glob(p)
                if pair and pair not in dir_patterns:
                    dir_patterns.append(pair)
        elif bucket == "config":
            cfg_patterns.extend(patterns)
            instr_patterns.extend(p for p in patterns if not p.startswith(("/", "~", "*")))

    return AgentType(
        id=agent_id,
        name=agent_name,
        instruction_patterns=tuple(instr_patterns),
        config_patterns=tuple(cfg_patterns),
        rule_patterns=tuple(rule_pats),
        directory_patterns=tuple(dir_patterns),
        core=data.get("core") is True,
        home_dir=str(data.get("home_dir") or ""),
        shared_names=tuple(str(n) for n in data.get("shared_names") or ()),
    )


def _build_agent_registry() -> dict[str, AgentType]:
    """Build agent registry from bundled framework/rules/*/config.yml files."""
    from reporails_cli.core.platform.config.bootstrap import get_rules_path
    from reporails_cli.core.platform.utils.utils import load_yaml_file

    registry: dict[str, AgentType] = {}
    rules_path = get_rules_path()
    if not rules_path or not rules_path.is_dir():
        return registry

    for config_path in sorted(rules_path.glob("*/config.yml")):
        try:
            data = load_yaml_file(config_path)
        except Exception:  # load_yaml_file can raise various errors
            logger.warning("Failed to load agent config %s — agent skipped", config_path, exc_info=True)
            continue
        if not data or not isinstance(data, dict):
            logger.warning("Agent config is empty or malformed: %s — agent skipped", config_path)
            continue
        agent_type = _parse_agent_config(data)
        if agent_type:
            registry[agent_type.id] = agent_type

    return registry


_agent_registry: dict[str, AgentType] | None = None


def get_known_agents() -> dict[str, AgentType]:
    """Get the agent registry, building from config.yml on first access."""
    global _agent_registry
    if _agent_registry is None:
        _agent_registry = _build_agent_registry()
    return _agent_registry


@dataclass
class DetectedAgent:
    """An agent detected in a project."""

    agent_type: AgentType
    instruction_files: list[Path] = field(default_factory=list)
    config_files: list[Path] = field(default_factory=list)
    rule_files: list[Path] = field(default_factory=list)
    detected_directories: dict[str, str] = field(default_factory=dict)


# Module-level cache for detected agents — avoids repeated glob scanning.
# Cache keyed on target path, cleared by clear_agent_cache().
_agent_cache: dict[str, list[DetectedAgent]] = {}


def clear_agent_cache() -> None:
    """Clear the agent detection cache. Called by --refresh.

    Also clears the downstream file-alias map — it is computed from the agent
    list, so an invalidated agent list invalidates the aliases too.
    """
    _agent_cache.clear()
    clear_alias_cache()


# ─── Public API ─────────────────────────────────────────────────────────


DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        # VCS
        ".git",
        ".svn",
        ".hg",
        # Python
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        # JS/TS
        "node_modules",
        # Build output
        "dist",
        "build",
        "target",
        "out",
        # Data / artifacts (instruction files never live here)
        "data",
        "datasets",
        # Vendored
        "vendor",
        # IDE / OS
        ".idea",
        # `.vscode` is deliberately absent: Copilot declares real config/mcp
        # surfaces there (`.vscode/{settings,mcp}.json`), pre-filtered out otherwise.
    }
)


def load_project_exclude_dirs(target: Path) -> frozenset[str]:
    """The built-in default excludes plus the project's `exclude_dirs`.

    Built-in defaults cover directories that never contain instruction files
    (VCS internals, caches, node_modules, data). The project's `exclude_dirs`
    (`.ails/config.yml`, `.ails/config.local.yml` and the global config)
    extend — not replace — these defaults.
    """
    return DEFAULT_EXCLUDE_DIRS | frozenset(get_project_config(target).exclude_dirs)


def detect_agents(
    target: Path,
    rules_paths: list[Path] | None = None,
) -> list[DetectedAgent]:
    """Detect coding agents in the target directory.

    Uses config.yml file_types from bundled framework for discovery.
    Per-surface include/exclude and Codex fallback filenames come from the
    project's `.ails/config.yml` (and `.ails/config.local.yml`).
    Cached per target path.
    """
    cache_key = str(target)
    cached = _agent_cache.get(cache_key)
    if cached is not None:
        return cached

    # Load project exclude_dirs early so discovery skips noise directories
    project_excludes = load_project_exclude_dirs(target)

    # Load project config for per-surface include/exclude + fallback filenames
    project_config = get_project_config(target)

    detected: list[DetectedAgent] = []

    known = get_known_agents()
    for agent_id, agent_type in known.items():
        # Fast marker check — skip agents with no footprint (avoids tree walks)
        if not (
            agent_has_marker(target, agent_type, known, project_excludes)
            or _config_names_agent(agent_id, project_config)
        ):
            continue

        # Config-driven discovery from bundled config.yml
        config_result = _discover_from_config(
            target, agent_id, rules_paths, project_excludes, project_config=project_config, repo_scoped=True
        )
        if config_result is None:
            continue

        instruction_files, rule_files, config_files = config_result

        # Detect directories (derived from config.yml patterns)
        detected_dirs: dict[str, str] = {}
        for label, dir_path in agent_type.directory_patterns:
            full_path = target / dir_path
            if full_path.is_dir() and any(full_path.iterdir()):
                detected_dirs[label] = dir_path + "/"

        # Include if we found any scannable files (instruction or rule)
        if instruction_files or rule_files:
            detected.append(
                DetectedAgent(
                    agent_type=agent_type,
                    instruction_files=instruction_files,
                    config_files=config_files,
                    rule_files=rule_files,
                    detected_directories=detected_dirs,
                )
            )

    detected = _disambiguate_codex_generic(detected, target, project_config)
    detected = _disambiguate_shared_files(detected, target)

    _agent_cache[cache_key] = detected
    return detected


def detect_single_agent(
    target: Path,
    agent_id: str,
    rules_paths: list[Path] | None = None,
) -> DetectedAgent | None:
    """Detect a single agent by ID, bypassing disambiguation."""
    agent_type = get_known_agents().get(agent_id)
    if not agent_type:
        return None

    config_result = _discover_from_config(
        target, agent_id, rules_paths, project_config=get_project_config(target), repo_scoped=True
    )
    if config_result is None:
        return None
    instruction_files, rule_files, config_files = config_result

    if not (instruction_files or rule_files):
        return None
    return DetectedAgent(
        agent_type=agent_type,
        instruction_files=instruction_files,
        config_files=config_files,
        rule_files=rule_files,
    )


def _disambiguate_codex_generic(
    detected: list[DetectedAgent], target: Path, project_config: ProjectConfig | None = None
) -> list[DetectedAgent]:
    """Resolve codex/generic ambiguity when both match on AGENTS.md.

    Four tiers: (1) AGENTS.override.md in project, (2) .codex/config.toml
    in project, (3) ~/.codex/config.toml + codex patterns in .gitignore,
    (4) the project's own config declares Codex fallback filenames.
    When codex confirmed → drop generic. Otherwise → drop codex.
    """
    codex = next((a for a in detected if a.agent_type.id == "codex"), None)
    generic = next((a for a in detected if a.agent_type.id == "generic"), None)
    if codex is None or generic is None:
        return detected

    codex_confirmed = (
        any(f.name == "AGENTS.override.md" for f in codex.instruction_files)  # Tier 1
        or bool(codex.config_files)  # Tier 2
        or _codex_global_heuristic(target)  # Tier 3
        or _config_names_agent("codex", project_config)  # Tier 4
    )
    drop = "generic" if codex_confirmed else "codex"
    return [a for a in detected if a.agent_type.id != drop]


def _codex_global_heuristic(target: Path) -> bool:
    """Tier 3: ~/.codex/config.toml exists AND .gitignore mentions codex patterns."""
    if not (Path.home() / ".codex" / "config.toml").exists():
        return False
    gitignore = target / ".gitignore"
    if not gitignore.exists():
        return False
    try:
        content = gitignore.read_text(encoding="utf-8")
    except OSError:
        return False
    return ".codex" in content or "AGENTS.override" in content


def _disambiguate_shared_files(detected: list[DetectedAgent], target: Path | None = None) -> list[DetectedAgent]:
    """Drop agents whose instruction files are entirely shared with other agents.

    AGENTS.md is a cross-agent standard — any project with it triggers detection
    for cursor, copilot, codex, antigravity, and generic. This function removes agents
    that found ONLY shared files (files claimed by 2+ agents), keeping agents that
    have at least one distinctive file. Generic is exempt (catch-all for AGENTS.md).
    A file in the agent's own directory (`.claude/skills/**` for claude) stays its own
    even when another agent also reads it.
    """
    if len(detected) <= 1:
        return detected

    # Count how many agents claim each file
    file_claim_count: Counter[Path] = Counter()
    for a in detected:
        for f in a.instruction_files:
            file_claim_count[f] += 1

    # Shared files = claimed by 2+ agents
    shared = {f for f, count in file_claim_count.items() if count >= 2}
    if not shared:
        return detected

    result: list[DetectedAgent] = []
    for a in detected:
        # Generic always stays — it's the catch-all for cross-agent files
        if a.agent_type.id == "generic":
            result.append(a)
            continue
        # Keep agent if it has at least one non-shared instruction file
        own_id = a.agent_type.id
        has_distinctive = any(
            f not in shared or (target is not None and _agent_namespace(f, target) == own_id)
            for f in a.instruction_files
        )
        # Also keep if it has agent-specific rule files or config files
        if has_distinctive or a.rule_files or a.config_files:
            result.append(a)
    return result


def _own_files(a: DetectedAgent) -> set[Path]:
    """Every file this agent claims — instruction, rule, and config combined."""
    return set(a.instruction_files) | set(a.rule_files) | set(a.config_files)


def _distinctive_agents(detected_agents: list[DetectedAgent], target: Path | None = None) -> list[DetectedAgent]:
    """Agents that are genuinely distinctive — not a generic alias, not another detected
    agent's cross-read (Copilot's config declares `.claude/rules/**` for cross-agent
    compatibility; that namespace is Claude's, not Copilot's, when Claude is also detected
    here — see `_all_cross_read`). `target=None` (no project root on hand, e.g. a unit
    test) still runs the generic-subset check; only the cross-read check needs it.
    """
    from reporails_cli.core.discovery.agent_discovery import _reads_nothing_of_its_own

    generic_files = next((_own_files(a) for a in detected_agents if a.agent_type.id == "generic"), set())
    other_ids = {a.agent_type.id for a in detected_agents}
    claims = Counter(f for a in detected_agents if a.agent_type.id != "generic" for f in _own_files(a))
    shared = frozenset(f for f, count in claims.items() if count > 1)
    return [
        a
        for a in detected_agents
        if a.agent_type.id != "generic"
        and not _own_files(a).issubset(generic_files)
        and not (target is not None and _reads_nothing_of_its_own(a, other_ids, target, shared))
    ]


def auto_detect_agent(detected_agents: list[DetectedAgent], target: Path | None = None) -> str:
    """Pick agent when exactly one distinctive agent is detected."""
    distinctive = _distinctive_agents(detected_agents, target)
    if len(distinctive) == 1:
        return distinctive[0].agent_type.id
    return ""


def resolve_agent(
    agent: str, detected_agents: list[DetectedAgent], target: Path | None = None
) -> tuple[str, bool, bool]:
    """Auto-detect step in agent resolution. Returns (agent, assumed, mixed)."""
    if agent:
        return agent, False, False
    auto = auto_detect_agent(detected_agents, target)
    if auto:
        return auto, True, False
    if len(_distinctive_agents(detected_agents, target)) > 1:
        return "", False, True
    return "", False, False


def filter_agents_by_id(agents: list[DetectedAgent], agent_id: str) -> list[DetectedAgent]:
    """Filter detected agents to only those matching agent_id."""
    return [agent for agent in agents if agent.agent_type.id == agent_id]


def _drop_agent_files(agents: list[DetectedAgent], drop: Any) -> list[DetectedAgent]:
    """Each agent with the instruction and rule files `drop(path)` rejects removed; an
    agent left with no instruction file is dropped."""
    filtered: list[DetectedAgent] = []
    for agent in agents:
        inst = [f for f in agent.instruction_files if not drop(f)]
        if inst:  # Only keep agent if it still has instruction files
            rules = [f for f in agent.rule_files if not drop(f)]
            filtered.append(
                DetectedAgent(agent.agent_type, inst, agent.config_files, rules, agent.detected_directories)
            )
    return filtered


def filter_agents_by_exclude_dirs(
    agents: list[DetectedAgent],
    target: Path,
    exclude_dirs: frozenset[str],
) -> list[DetectedAgent]:
    """Remove files in excluded directories. Drops agents with no remaining files."""
    if not exclude_dirs:
        return agents
    return _drop_agent_files(agents, lambda f: is_excluded(f, target, exclude_dirs))


def filter_agents_by_exclude_files(
    agents: list[DetectedAgent],
    target: Path,
    exclude_files: list[str] | None,
) -> list[DetectedAgent]:
    """Remove files matching an exclude glob (rel. to target). Drops agents with no remaining files."""
    if not exclude_files:
        return agents
    return _drop_agent_files(agents, lambda f: matches_any_glob(f, exclude_files, target))


def get_all_instruction_files(target: Path, agents: list[DetectedAgent] | None = None) -> list[Path]:
    """Get deduplicated instruction + rule files for detected agents."""
    raw: list[Path] = []
    for detected in agents if agents is not None else detect_agents(target):
        raw.extend(detected.instruction_files)
        raw.extend(detected.rule_files)
    canonical, aliases = _dedupe_with_aliases(raw)
    _store_alias_cache(target, aliases)
    return canonical


def get_all_scannable_files(target: Path, agents: list[DetectedAgent] | None = None) -> list[Path]:
    """Get all scannable files (instruction + rule + config) for detected agents."""
    raw: list[Path] = []
    for detected in agents if agents is not None else detect_agents(target):
        raw.extend(detected.instruction_files)
        raw.extend(detected.rule_files)
        raw.extend(detected.config_files)
    canonical, aliases = _dedupe_with_aliases(raw)
    _store_alias_cache(target, aliases)
    return canonical
