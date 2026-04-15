"""Agent definitions - coding agent agnostic discovery.  # pylint: disable=too-many-lines

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
    agent_name = data.get("name", agent_id)
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
        except Exception:
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


def _ci_glob(target: Path, pattern: str) -> list[Path]:
    """Case-insensitive glob for root-level filenames, standard glob for nested."""
    parts = Path(pattern).parts
    if len(parts) == 1 and "*" not in pattern:
        # Root-level exact filename — match case-insensitively
        lower = pattern.lower()
        try:
            return [p for p in target.iterdir() if p.name.lower() == lower and not p.is_dir()]
        except OSError:
            return []
    return list(target.glob(pattern))


# ─── Config-driven discovery ────────────────────────────────────────────


def _load_config_file_types(
    agent_id: str,
    rules_paths: list[Path] | None = None,
) -> dict[str, Any] | None:
    """Load file_types section from agent config.yml.

    Searches rules_paths first, then falls back to the default config path.
    Returns the file_types dict or None if not found.
    """

    from reporails_cli.core.bootstrap import get_agent_config_path

    candidates: list[Path] = []
    if rules_paths:
        candidates.extend(rp / agent_id / "config.yml" for rp in rules_paths)
    candidates.append(get_agent_config_path(agent_id))

    for path in candidates:
        if not path.exists():
            continue
        try:
            from reporails_cli.core.utils import load_yaml_file

            data = load_yaml_file(path)
            if not data:
                logger.warning("Agent config is empty: %s", path)
                continue
            ft = data.get("file_types")
            if ft and isinstance(ft, dict):
                return dict(ft)
        except Exception:
            logger.debug("Failed to load agent config %s", path, exc_info=True)
            continue
    return None


def _categorize_file_type(patterns: list[str], properties: dict[str, str]) -> str:
    """Categorize a file_type entry as instruction/rule/config/skip.

    Uses file_type properties from config.yml:
    - format: schema_validated → config
    - scope: path_scoped → rule (scoped rule files)
    - directory-only or system paths → skip
    - everything else → instruction
    """
    # Skip directory-only patterns (e.g., ".claude/memory/")
    if all(p.endswith("/") for p in patterns):
        return "skip"
    # Skip absolute system paths (managed configs)
    if all(p.startswith(("/", "C:")) for p in patterns):
        return "skip"
    # Schema-validated files → config bucket
    if properties.get("format") == "schema_validated":
        return "config"
    # Path-scoped markdown → rule files bucket
    if properties.get("scope") == "path_scoped":
        return "rule"
    # Everything else (main, skill, override) → instruction bucket
    return "instruction"


def _is_excluded(path: Path, target: Path, exclude_dirs: frozenset[str]) -> bool:
    """Check if any path component is in the exclusion set."""
    if not exclude_dirs:
        return False
    try:
        rel = path.relative_to(target)
    except ValueError:
        return False
    return bool(exclude_dirs & set(rel.parts))


# Directories that never contain instruction files — skipped unconditionally.
# Project-specific exclusions come from .ails/config.yml exclude_dirs.
_ALWAYS_SKIP = frozenset({".git", "__pycache__", "node_modules"})


def _walk_glob(root: Path, filename: str, exclude_dirs: frozenset[str]) -> list[Path]:
    """Walk directory tree matching a filename, skipping excluded dirs.

    Much faster than Path.glob("**/name") because it prunes excluded
    subtrees during traversal instead of filtering afterwards.
    Uses os.scandir for efficient directory traversal.
    """
    skip = exclude_dirs | _ALWAYS_SKIP
    lower_name = filename.lower()
    results: list[Path] = []
    stack = [str(root)]
    while stack:
        current = stack.pop()
        try:
            scanner = os.scandir(current)
        except OSError:
            continue
        with scanner:
            for entry in scanner:
                name = entry.name
                if name.lower() == lower_name:
                    try:
                        is_match = entry.is_file(follow_symlinks=True)
                    except OSError:
                        # Broken/circular symlink — include it so downstream
                        # code can report the error properly
                        is_match = entry.is_symlink()
                    if is_match:
                        results.append(Path(entry.path))
                elif entry.is_dir(follow_symlinks=False) and name not in skip:
                    stack.append(entry.path)
    return results


def _glob_file_type_patterns(
    target: Path,
    patterns: list[str],
    exclude_dirs: frozenset[str] = frozenset(),
) -> list[Path]:
    """Glob file_type patterns against target directory.

    For recursive (**/) patterns with a literal filename (e.g., **/CLAUDE.md),
    uses pruning walk to avoid traversing excluded directory trees.
    Falls back to Path.glob for wildcard filenames (e.g., **/*.md).

    External paths (~/... and /absolute/...) are resolved outside the project
    directory. These are part of the instruction surface (user-level config,
    managed policies, auto-memory) even though they live outside the repo.
    """
    found: list[Path] = []
    for pattern in patterns:
        # Skip directory-only patterns
        if pattern.endswith("/"):
            continue

        # External paths: ~/... or /absolute/... or C:/...
        if pattern.startswith("~") or pattern.startswith("/") or (len(pattern) > 1 and pattern[1] == ":"):
            expanded = Path(pattern).expanduser()
            if "*" in pattern:
                # Glob external pattern (e.g., ~/.claude/projects/*/memory/MEMORY.md)
                # For project-scoped patterns (containing */), replace * with
                # the current project's directory key to avoid matching other projects.
                expanded_str = str(expanded)
                if "/projects/*/" in expanded_str:
                    project_key = str(target.resolve()).replace("/", "-")
                    expanded_str = expanded_str.replace("/projects/*/", f"/projects/{project_key}/")
                import glob as _glob

                found.extend(Path(p) for p in _glob.glob(expanded_str) if Path(p).is_file())
            elif expanded.is_file():
                found.append(expanded)
            continue

        parts = Path(pattern).parts
        filename = parts[-1] if parts else ""

        # Use pruning walk only for recursive patterns with literal filenames
        if "**" in pattern and "*" not in filename:
            # Extract prefix before ** (e.g., ".claude/skills/**/SKILL.md" → ".claude/skills")
            prefix_parts = []
            for p in parts:
                if "**" in p:
                    break
                prefix_parts.append(p)
            walk_root = target / Path(*prefix_parts) if prefix_parts else target
            if walk_root.is_dir():
                found.extend(
                    m
                    for m in _walk_glob(walk_root, filename, exclude_dirs)
                    if not _is_excluded(m, target, exclude_dirs)
                )
        else:
            # Non-recursive or wildcard filename — use standard glob
            found.extend(m for m in _ci_glob(target, pattern) if not _is_excluded(m, target, exclude_dirs))
    return found


def _discover_from_config(
    target: Path,
    agent_id: str,
    rules_paths: list[Path] | None = None,
    extra_exclude_dirs: frozenset[str] = frozenset(),
) -> tuple[list[Path], list[Path], list[Path]] | None:
    """Discover files using config.yml file_types.

    Returns (instruction_files, rule_files, config_files) or None if
    no config.yml is available for this agent.
    """
    file_types = _load_config_file_types(agent_id, rules_paths)
    if file_types is None:
        return None

    instruction_files: list[Path] = []
    rule_files: list[Path] = []
    config_files: list[Path] = []

    for spec in file_types.values():
        if not isinstance(spec, dict):
            continue
        patterns = _extract_patterns(spec)
        properties = _extract_properties(spec)

        bucket = _categorize_file_type(patterns, properties)
        if bucket == "skip":
            continue

        found = _glob_file_type_patterns(target, patterns, extra_exclude_dirs)

        if bucket == "instruction":
            instruction_files.extend(found)
        elif bucket == "rule":
            rule_files.extend(found)
        elif bucket == "config":
            config_files.extend(found)

    return (
        sorted(set(instruction_files)),
        sorted(set(rule_files)),
        sorted(set(config_files)),
    )


# ─── Public API ─────────────────────────────────────────────────────────


def _load_project_exclude_dirs(target: Path) -> frozenset[str]:
    """Load exclude_dirs from .ails/config.yml if it exists."""
    config_path = target / ".ails" / "config.yml"
    if not config_path.exists():
        return frozenset()
    try:
        from reporails_cli.core.utils import load_yaml_file

        data = load_yaml_file(config_path)
        if not data:
            logger.warning("Project config is empty: %s", config_path)
            return frozenset()
        dirs = data.get("exclude_dirs", [])
        if isinstance(dirs, list):
            return frozenset(str(d) for d in dirs)
    except Exception:
        logger.warning("Failed to load project config %s", config_path, exc_info=True)
    return frozenset()


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
