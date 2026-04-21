"""Agent definitions - coding agent agnostic discovery.

File discovery is driven by agent config.yml (file_types section) bundled
in framework/rules/*/config.yml. The agent registry is built at first
access from these configs — no hardcoded agent list.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reporails_cli.core.agent_discovery import categorize_file_type as _categorize_file_type
from reporails_cli.core.agent_discovery import discover_from_config as _discover_from_config

logger = logging.getLogger(__name__)


def _extract_patterns(spec: dict[str, Any]) -> list[str]:
    """Extract all file patterns from a file type spec.

    Supports both v0.3.0 (patterns at top level) and v0.5.0 (patterns
    inside scopes). Returns a flat list of all patterns across all scopes.
    """
    # v0.3.0: patterns at top level
    patterns = spec.get("patterns", [])
    if isinstance(patterns, str):
        patterns = [patterns]
    if patterns:
        return list(patterns)

    # v0.5.0: patterns inside scopes
    scopes = spec.get("scopes", {})
    if not isinstance(scopes, dict):
        return []
    all_patterns: list[str] = []
    for scope_spec in scopes.values():
        if not isinstance(scope_spec, dict):
            continue
        scope_patterns = scope_spec.get("patterns", [])
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


def _dir_prefix_from_glob(pattern: str) -> tuple[str, str] | None:
    """Extract (label, dir_path) from a glob pattern like '.cursor/rules/**/*.mdc'."""
    parts = Path(pattern).parts
    dir_parts = []
    for part in parts:
        if "*" in part:
            break
        dir_parts.append(part)
    if not dir_parts:
        return None
    return dir_parts[-1], str(Path(*dir_parts))


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
                pair = _dir_prefix_from_glob(p)
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
    )


def _build_agent_registry() -> dict[str, AgentType]:
    """Build agent registry from bundled framework/rules/*/config.yml files."""
    from reporails_cli.core.bootstrap import get_rules_path
    from reporails_cli.core.utils import load_yaml_file

    registry: dict[str, AgentType] = {}
    rules_path = get_rules_path()
    if not rules_path or not rules_path.is_dir():
        return registry

    for config_path in sorted(rules_path.glob("*/config.yml")):
        try:
            data = load_yaml_file(config_path)
        except Exception:  # load_yaml_file can raise various errors
            continue
        if not data or not isinstance(data, dict):
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
    """Clear the agent detection cache. Called by --refresh."""
    _agent_cache.clear()


# ─── Public API ─────────────────────────────────────────────────────────


_DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
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
        ".vscode",
    }
)


def _load_project_exclude_dirs(target: Path) -> frozenset[str]:
    """Load exclude_dirs from .ails/config.yml, merged with built-in defaults.

    Built-in defaults cover directories that never contain instruction files
    (VCS internals, caches, node_modules, data). Project-level exclude_dirs
    extend — not replace — these defaults.
    """
    config_path = target / ".ails" / "config.yml"
    if not config_path.exists():
        return _DEFAULT_EXCLUDE_DIRS
    try:
        from reporails_cli.core.utils import load_yaml_file

        data = load_yaml_file(config_path)
        if not data:
            logger.warning("Project config is empty: %s", config_path)
            return _DEFAULT_EXCLUDE_DIRS
        dirs = data.get("exclude_dirs", [])
        if isinstance(dirs, list):
            return _DEFAULT_EXCLUDE_DIRS | frozenset(str(d) for d in dirs)
    except Exception:  # glob expansion; skip unresolvable patterns
        logger.warning("Failed to load project config %s", config_path, exc_info=True)
    return _DEFAULT_EXCLUDE_DIRS


def _agent_has_marker(target: Path, agent_type: AgentType) -> bool:
    """Fast existence check — does this agent likely exist in the project?

    Checks for root-level instruction files or agent-specific directories.
    Returns False only when we're certain the agent is absent (a few stat() calls).
    Uses os.path.lexists to detect symlinks (even broken/circular ones).

    Root-level files are matched case-insensitively (claude.md == CLAUDE.md)
    because repos in the wild use both conventions.
    """
    # Build lowercase index of root files once per call (cheap — root only)
    try:
        root_lower = {
            entry.name.lower(): entry.name
            for entry in os.scandir(target)
            if entry.is_file(follow_symlinks=False) or entry.is_symlink()
        }
    except OSError:
        root_lower = {}

    for pattern in agent_type.instruction_patterns:
        # Patterns with path separators or globs — check exact path
        if "/" in pattern or "*" in pattern:
            if os.path.lexists(target / pattern):
                return True
        else:
            # Root-level file — case-insensitive match
            if pattern.lower() in root_lower:
                return True
    return any((target / dir_path).is_dir() for _, dir_path in agent_type.directory_patterns)


def detect_agents(  # pylint: disable=too-many-locals
    target: Path,
    rules_paths: list[Path] | None = None,
) -> list[DetectedAgent]:
    """Detect coding agents in the target directory.

    Uses config.yml file_types from bundled framework for discovery.
    Cached per target path.
    """
    cache_key = str(target)
    cached = _agent_cache.get(cache_key)
    if cached is not None:
        return cached

    # Load project exclude_dirs early so discovery skips noise directories
    project_excludes = _load_project_exclude_dirs(target)

    detected: list[DetectedAgent] = []

    for agent_id, agent_type in get_known_agents().items():
        # Fast marker check — skip agents with no footprint (avoids tree walks)
        if not _agent_has_marker(target, agent_type):
            continue

        # Config-driven discovery from bundled config.yml
        config_result = _discover_from_config(target, agent_id, rules_paths, project_excludes)
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

    detected = _disambiguate_codex_generic(detected, target)
    detected = _disambiguate_shared_files(detected)

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

    config_result = _discover_from_config(target, agent_id, rules_paths)
    if config_result is None:
        return None
    instruction_files, rule_files, config_files = config_result

    if not instruction_files:
        return None
    return DetectedAgent(
        agent_type=agent_type,
        instruction_files=instruction_files,
        config_files=config_files,
        rule_files=rule_files,
    )


def _disambiguate_codex_generic(detected: list[DetectedAgent], target: Path) -> list[DetectedAgent]:
    """Resolve codex/generic ambiguity when both match on AGENTS.md.

    Three tiers: (1) AGENTS.override.md in project, (2) .codex/config.toml
    in project, (3) ~/.codex/config.toml + codex patterns in .gitignore.
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


def _disambiguate_shared_files(detected: list[DetectedAgent]) -> list[DetectedAgent]:
    """Drop agents whose instruction files are entirely shared with other agents.

    AGENTS.md is a cross-agent standard — any project with it triggers detection
    for cursor, copilot, codex, gemini, and generic. This function removes agents
    that found ONLY shared files (files claimed by 2+ agents), keeping agents that
    have at least one distinctive file. Generic is exempt (catch-all for AGENTS.md).
    """
    if len(detected) <= 1:
        return detected

    # Count how many agents claim each file
    from collections import Counter

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
        has_distinctive = any(f not in shared for f in a.instruction_files)
        # Also keep if it has agent-specific rule files or config files
        if has_distinctive or a.rule_files or a.config_files:
            result.append(a)
    return result


def _distinctive_agents(detected_agents: list[DetectedAgent]) -> list[DetectedAgent]:
    """Return agents that are genuinely distinctive (not just generic aliases).

    Agents whose instruction files are entirely a subset of generic's files
    (e.g. codex matching only AGENTS.md) are not distinctive enough to count.
    """
    generic_files: set[Path] = set()
    for a in detected_agents:
        if a.agent_type.id == "generic":
            generic_files = set(a.instruction_files)
            break
    return [
        a
        for a in detected_agents
        if a.agent_type.id != "generic" and not set(a.instruction_files).issubset(generic_files)
    ]


def auto_detect_agent(detected_agents: list[DetectedAgent]) -> str:
    """Pick agent when exactly one distinctive agent is detected."""
    distinctive = _distinctive_agents(detected_agents)
    if len(distinctive) == 1:
        return distinctive[0].agent_type.id
    return ""


def resolve_agent(agent: str, detected_agents: list[DetectedAgent]) -> tuple[str, bool, bool]:
    """Auto-detect step in agent resolution. Returns (agent, assumed, mixed)."""
    if agent:
        return agent, False, False
    auto = auto_detect_agent(detected_agents)
    if auto:
        return auto, True, False
    if len(_distinctive_agents(detected_agents)) > 1:
        return "", False, True
    return "", False, False


def filter_agents_by_id(agents: list[DetectedAgent], agent_id: str) -> list[DetectedAgent]:
    """Filter detected agents to only those matching agent_id."""
    return [agent for agent in agents if agent.agent_type.id == agent_id]


def _path_parts(file: Path, target: Path) -> set[str]:
    """Return the set of path components of file relative to target."""
    try:
        return set(file.relative_to(target).parts)
    except ValueError:
        return set()


def filter_agents_by_exclude_dirs(
    agents: list[DetectedAgent],
    target: Path,
    exclude_dirs: list[str] | None,
) -> list[DetectedAgent]:
    """Remove files in excluded directories. Drops agents with no remaining files."""
    if not exclude_dirs:
        return agents
    exclude_set = set(exclude_dirs)
    filtered: list[DetectedAgent] = []
    for agent in agents:
        inst = [f for f in agent.instruction_files if not (_path_parts(f, target) & exclude_set)]
        rules = [f for f in agent.rule_files if not (_path_parts(f, target) & exclude_set)]
        if inst:  # Only keep agent if it still has instruction files
            filtered.append(
                DetectedAgent(
                    agent_type=agent.agent_type,
                    instruction_files=inst,
                    config_files=agent.config_files,
                    rule_files=rules,
                    detected_directories=agent.detected_directories,
                )
            )
    return filtered


def get_all_instruction_files(target: Path, agents: list[DetectedAgent] | None = None) -> list[Path]:
    """Get deduplicated instruction + rule files for detected agents."""
    all_files: set[Path] = set()

    for detected in agents if agents is not None else detect_agents(target):
        all_files.update(detected.instruction_files)
        all_files.update(detected.rule_files)

    return sorted(all_files)


def get_all_scannable_files(target: Path, agents: list[DetectedAgent] | None = None) -> list[Path]:
    """Get all scannable files (instruction + rule + config) for detected agents."""
    all_files: set[Path] = set()

    for detected in agents if agents is not None else detect_agents(target):
        all_files.update(detected.instruction_files)
        all_files.update(detected.rule_files)
        all_files.update(detected.config_files)

    return sorted(all_files)
