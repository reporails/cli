"""Agent definitions - coding agent agnostic discovery.

File discovery is driven by agent config.yml (file_types section) bundled
in framework/rules/*/config.yml. The agent registry is built at first
access from these configs — no hardcoded agent list.
"""

from __future__ import annotations

import functools
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reporails_cli.core.discovery.agent_config import (
    categorize_file_type,
    extract_patterns,
    extract_properties,
    iter_agent_configs,
)
from reporails_cli.core.discovery.agent_discovery import discover_from_config
from reporails_cli.core.discovery.agent_markers import agent_has_marker, dir_prefix_from_glob
from reporails_cli.core.discovery.exclusions import load_project_exclude_dirs
from reporails_cli.core.discovery.file_aliases import clear_alias_cache, dedupe_with_aliases, store_alias_cache
from reporails_cli.core.discovery.read_gates import reads_as_fallback
from reporails_cli.core.discovery.surface_config import config_names_agent
from reporails_cli.core.platform.config.config import get_project_config, get_rules_path

if TYPE_CHECKING:
    from reporails_cli.core.discovery.exclusions import RunExclusions
    from reporails_cli.core.platform.dto.results import ProjectConfig


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
        patterns = extract_patterns(spec)
        properties = extract_properties(spec)

        bucket = categorize_file_type(patterns, properties)

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
    registry: dict[str, AgentType] = {}
    rules_path = get_rules_path()
    if not rules_path or not rules_path.is_dir():
        return registry

    for data in iter_agent_configs(rules_path):
        agent_type = _parse_agent_config(data)
        if agent_type:
            registry[agent_type.id] = agent_type

    return registry


@functools.cache
def get_known_agents() -> dict[str, AgentType]:
    """Get the agent registry, building from config.yml on first access."""
    return _build_agent_registry()


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


def _detect_agent(
    target: Path,
    agent_type: AgentType,
    *,
    known: dict[str, AgentType],
    rules_paths: list[Path] | None,
    project_excludes: frozenset[str],
    project_config: ProjectConfig | None,
) -> DetectedAgent | None:
    """The agent's detected files and directories under `target`, None when it has no scannable footprint."""
    agent_id = agent_type.id
    # Fast marker check — skip agents with no footprint (avoids tree walks)
    if not (
        agent_has_marker(target, agent_type, known, project_excludes) or config_names_agent(agent_id, project_config)
    ):
        return None

    # Config-driven discovery from bundled config.yml
    config_result = discover_from_config(
        target, agent_id, rules_paths, project_excludes, project_config=project_config, repo_scoped=True
    )
    if config_result is None:
        return None
    instruction_files, rule_files, config_files = config_result
    # Include only when we found scannable files (instruction or rule)
    if not (instruction_files or rule_files):
        return None

    # Detect directories (derived from config.yml patterns)
    detected_dirs: dict[str, str] = {}
    for label, dir_path in agent_type.directory_patterns:
        full_path = target / dir_path
        if full_path.is_dir() and any(full_path.iterdir()):
            detected_dirs[label] = dir_path + "/"
    return DetectedAgent(
        agent_type=agent_type,
        instruction_files=instruction_files,
        config_files=config_files,
        rule_files=rule_files,
        detected_directories=detected_dirs,
    )


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

    known = get_known_agents()
    detected = [
        agent
        for agent_type in known.values()
        if (
            agent := _detect_agent(
                target,
                agent_type,
                known=known,
                rules_paths=rules_paths,
                project_excludes=project_excludes,
                project_config=project_config,
            )
        )
        is not None
    ]

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

    config_result = discover_from_config(
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
        or config_names_agent("codex", project_config)  # Tier 4
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


# Coding-agent home directories whose name differs from the agent's own id
# (Copilot's is `.github/`, Antigravity's is `.gemini/`) plus the Agent Skills
# standard's shared `.agents/` home, which is `generic`'s own namespace, not any
# one coding agent's — a project with nothing but `.agents/skills/**` cross-reads
# has no single specific owner among the coding agents.
_NAMESPACE_ALIASES = {"github": "copilot", "gemini": "antigravity", "agents": "generic"}


def _agent_namespace(path: Path, target: Path) -> str | None:
    """The agent id that natively owns the on-disk namespace `path` sits under
    (`.claude/x` -> `"claude"`, `.github/x` -> `"copilot"` via `_NAMESPACE_ALIASES`),
    or `None` for a root-level file (no dot-directory) or a path outside `target` —
    neither carries a namespace to attribute a cross-read to."""
    try:
        parts = path.relative_to(target).parts
    except ValueError:
        return None
    if not parts or not (parts[0].startswith(".") and len(parts[0]) > 1):
        return None
    dirname = parts[0][1:]
    return _NAMESPACE_ALIASES.get(dirname, dirname)


def _is_project_root_file(path: Path, target: Path) -> bool:
    """True for a file directly at `target`'s root (no dot-directory, no subdirectory) —
    real native evidence for whichever agent's own pattern matched it (`CLAUDE.md`,
    root `AGENTS.md`), unlike a NESTED un-namespaced file reached only through a
    recursive `**/AGENTS.md`-style cross-agent-standard glob."""
    try:
        parts = path.relative_to(target).parts
    except ValueError:
        return False
    return len(parts) == 1


def _all_cross_read(
    files: set[Path], own_id: str, other_ids: set[str], target: Path, shared: frozenset[Path] = frozenset()
) -> bool:
    """True when `files` establishes no distinctiveness of `own_id`'s own: none sits in
    `own_id`'s own namespace or at a project-root main-file path, and at least one sits in
    another DETECTED agent's own namespace. A nobody's-specific shared surface
    (`.agents/skills/**`, which resolves to `generic` — not itself a distinctive candidate
    in this loop) is neutral: it neither grants nor costs distinctiveness by itself, so it
    alone can never block the exclusion the way requiring EVERY file to positively
    cross-read someone else would (a Copilot project cross-reading both Claude's
    `.claude/**` and the shared `.agents/skills/**`, with nothing of its own, must still
    exclude Copilot). A project-root file in `shared` (one another detected agent also
    reads, like a root `AGENTS.md` Claude reads when the project has no `CLAUDE.md`) is
    neutral the same way. Empty `files` is never cross-read (there is nothing to read)."""
    if not files:
        return False
    if any(
        _agent_namespace(f, target) == own_id or (_is_project_root_file(f, target) and f not in shared) for f in files
    ):
        return False
    return any((ns := _agent_namespace(f, target)) is not None and ns != own_id and ns in other_ids for f in files)


def _reads_nothing_of_its_own(agent: DetectedAgent, other_ids: set[str], target: Path, shared: frozenset[Path]) -> bool:
    """True when `agent` is no distinctive agent of its own: its files are all cross-reads
    (`_all_cross_read`), or every instruction and rule file it claims is one it reads only
    in place of its own main file (Claude and `AGENTS.md`) that another detected agent
    also claims -- a Codex project's `AGENTS.md` does not make Claude a second agent."""
    own_id = agent.agent_type.id
    content = [*agent.instruction_files, *agent.rule_files]
    if content and all(f in shared and reads_as_fallback(own_id, f) for f in content):
        return True
    return _all_cross_read(_own_files(agent), own_id, other_ids, target, shared)


def partition_by_native_owner(detected_agents: list[DetectedAgent], target: Path) -> dict[str, str]:
    """Map every file a non-generic detected agent claims to its rule-running attribution:
    the DISTINCTIVE agent that natively owns it (its own on-disk namespace, or a
    project-root main-file path), or `"generic"` when no currently-distinctive agent
    natively owns it -- a shared cross-agent standard (`.agents/skills/**`) or a nested
    `AGENTS.md` no agent's own namespace claims runs the core rule set only, exactly as a
    plain single-agent project's own unclaimed files would. This never drops a file from
    the map -- it only routes each one to the right ruleset. Keyed by `path.as_posix()` to match
    `FileRecord.path` and `Path` instruction-file entries directly."""
    distinctive_ids = {a.agent_type.id for a in _distinctive_agents(detected_agents, target)}
    claimants: dict[Path, list[str]] = {}
    for detected in detected_agents:
        if detected.agent_type.id == "generic":
            continue
        for f in _own_files(detected):
            claimants.setdefault(f, []).append(detected.agent_type.id)

    owner_by_path: dict[str, str] = {}
    for f, claimant_ids in claimants.items():
        # A file only ONE detected agent claims at all (its filename/pattern isn't a
        # cross-agent standard several registries share) is unambiguous native evidence
        # for that agent the moment it stays distinctive -- a nested `CLAUDE.md` under a
        # subproject (`packages/web/CLAUDE.md`) is real claude ownership even though it
        # sits neither at the project root nor inside claude's own `.claude/` namespace.
        # The namespace/root-file tie-break below is only needed once MULTIPLE agents
        # claim the same path (a shared standard like root `AGENTS.md`), where the
        # claim alone can't say which detected agent, if any, really owns it here.
        if len(claimant_ids) == 1 and claimant_ids[0] in distinctive_ids:
            owner_by_path[f.as_posix()] = claimant_ids[0]
            continue
        owner = "generic"
        # An agent that reads the file only in place of its own main file (Claude and a
        # root `AGENTS.md`) yields it to an agent that reads it natively.
        fallback = {cid: reads_as_fallback(cid, f) for cid in claimant_ids}
        for cid in sorted(claimant_ids, key=fallback.__getitem__):
            if cid in distinctive_ids and (_agent_namespace(f, target) == cid or _is_project_root_file(f, target)):
                owner = cid
                break
        owner_by_path[f.as_posix()] = owner
    return owner_by_path


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


def _drop_agent_files(agents: list[DetectedAgent], drop: Callable[[Path], bool]) -> list[DetectedAgent]:
    """Each agent with the instruction, rule and config files `drop(path)` rejects removed. An
    agent is kept while at least one instruction or rule file survives, and dropped when
    none does."""
    filtered: list[DetectedAgent] = []
    for agent in agents:
        inst = [f for f in agent.instruction_files if not drop(f)]
        rules = [f for f in agent.rule_files if not drop(f)]
        configs = [f for f in agent.config_files if not drop(f)]
        if inst or rules:
            filtered.append(DetectedAgent(agent.agent_type, inst, configs, rules, agent.detected_directories))
    return filtered


def filter_agents_by_exclusions(agents: list[DetectedAgent], exclusions: RunExclusions) -> list[DetectedAgent]:
    """Remove the files the run's exclusions leave out. Drops an agent left with no instruction or rule files."""
    if not exclusions.dirs and not exclusions.files:
        return agents
    return _drop_agent_files(agents, exclusions.leaves_out)


def get_all_instruction_files(target: Path, agents: list[DetectedAgent] | None = None) -> list[Path]:
    """Get deduplicated instruction + rule files for detected agents."""
    raw: list[Path] = []
    for detected in agents if agents is not None else detect_agents(target):
        raw.extend(detected.instruction_files)
        raw.extend(detected.rule_files)
    canonical, aliases = dedupe_with_aliases(raw)
    store_alias_cache(target, aliases)
    return canonical


def get_all_scannable_files(target: Path, agents: list[DetectedAgent] | None = None) -> list[Path]:
    """Get all scannable files (instruction + rule + config) for detected agents."""
    raw: list[Path] = []
    for detected in agents if agents is not None else detect_agents(target):
        raw.extend(detected.instruction_files)
        raw.extend(detected.rule_files)
        raw.extend(detected.config_files)
    canonical, aliases = dedupe_with_aliases(raw)
    store_alias_cache(target, aliases)
    return canonical
