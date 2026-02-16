"""Agent definitions - coding agent agnostic discovery.

Supports multiple AI coding assistants:
- Claude (Anthropic)
- Cursor
- Windsurf
- GitHub Copilot
- Aider
- Generic/custom
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AgentType:
    """Definition of a coding agent's file conventions."""

    id: str
    name: str
    instruction_patterns: tuple[str, ...]  # Glob patterns for instruction files
    config_patterns: tuple[str, ...]  # Glob patterns for config files
    rule_patterns: tuple[str, ...]  # Glob patterns for rule/snippet files
    directory_patterns: tuple[tuple[str, str], ...] = ()  # (label, dir_path) pairs


# Known coding agents and their conventions
KNOWN_AGENTS: dict[str, AgentType] = {
    "claude": AgentType(
        id="claude",
        name="Claude (Anthropic)",
        instruction_patterns=("CLAUDE.md", "**/CLAUDE.md"),
        config_patterns=(".claude/settings.json", ".claude/mcp.json"),
        rule_patterns=(".claude/rules/*.md", ".claude/rules/**/*.md", ".claude/skills/**/*.md"),
        directory_patterns=(
            ("rules", ".claude/rules"),
            ("skills", ".claude/skills"),
            ("tasks", ".claude/tasks"),
        ),
    ),
    "cursor": AgentType(
        id="cursor",
        name="Cursor",
        instruction_patterns=(".cursorrules", ".cursor/rules/*.md"),
        config_patterns=(".cursor/settings.json",),
        rule_patterns=(".cursor/rules/*.md",),
        directory_patterns=(("rules", ".cursor/rules"),),
    ),
    "windsurf": AgentType(
        id="windsurf",
        name="Windsurf",
        instruction_patterns=(".windsurfrules",),
        config_patterns=(),
        rule_patterns=(),
    ),
    "copilot": AgentType(
        id="copilot",
        name="GitHub Copilot",
        instruction_patterns=(".github/copilot-instructions.md",),
        config_patterns=(),
        rule_patterns=(),
    ),
    "aider": AgentType(
        id="aider",
        name="Aider",
        instruction_patterns=(".aider.conf.yml", "CONVENTIONS.md"),
        config_patterns=(".aider.conf.yml",),
        rule_patterns=(),
    ),
    "generic": AgentType(
        id="generic",
        name="Generic AI Instructions",
        instruction_patterns=("AGENTS.md", ".ai/instructions.md", ".ai/**/*.md"),
        config_patterns=(),
        rule_patterns=(".ai/rules/*.md",),
    ),
}


@dataclass
class DetectedAgent:
    """An agent detected in a project."""

    agent_type: AgentType
    instruction_files: list[Path] = field(default_factory=list)
    config_files: list[Path] = field(default_factory=list)
    rule_files: list[Path] = field(default_factory=list)
    detected_directories: dict[str, str] = field(default_factory=dict)


# Module-level cache for detected agents — glob scanning is expensive (~100ms
# on large repos). Cache keyed on target path, cleared by clear_agent_cache().
_agent_cache: dict[str, list[DetectedAgent]] = {}


def clear_agent_cache() -> None:
    """Clear the agent detection cache. Called by --refresh."""
    _agent_cache.clear()


def detect_agents(target: Path) -> list[DetectedAgent]:
    """
    Detect which coding agents are configured in the target directory.

    Scans for known file patterns and returns detected agents with their files.
    Results are cached per target path for MCP performance.

    Args:
        target: Project root to scan

    Returns:
        List of detected agents with their associated files
    """
    cache_key = str(target)
    cached = _agent_cache.get(cache_key)
    if cached is not None:
        return cached

    detected: list[DetectedAgent] = []

    for agent_type in KNOWN_AGENTS.values():
        instruction_files: list[Path] = []
        config_files: list[Path] = []
        rule_files: list[Path] = []

        # Find instruction files
        for pattern in agent_type.instruction_patterns:
            instruction_files.extend(target.glob(pattern))

        # Find config files
        for pattern in agent_type.config_patterns:
            config_files.extend(target.glob(pattern))

        # Find rule files
        for pattern in agent_type.rule_patterns:
            rule_files.extend(target.glob(pattern))

        # Detect directories
        detected_dirs: dict[str, str] = {}
        for label, dir_path in agent_type.directory_patterns:
            full_path = target / dir_path
            if full_path.is_dir() and any(full_path.iterdir()):
                detected_dirs[label] = dir_path + "/"

        # Only include if we found at least one instruction file
        if instruction_files:
            detected.append(
                DetectedAgent(
                    agent_type=agent_type,
                    instruction_files=sorted(set(instruction_files)),
                    config_files=sorted(set(config_files)),
                    rule_files=sorted(set(rule_files)),
                    detected_directories=detected_dirs,
                )
            )

    _agent_cache[cache_key] = detected
    return detected


def filter_agents_by_id(agents: list[DetectedAgent], agent_id: str) -> list[DetectedAgent]:
    """
    Filter detected agents by agent ID.

    Args:
        agents: List of detected agents
        agent_id: Agent identifier to filter by (e.g., "claude", "copilot")

    Returns:
        List containing only the specified agent if found, empty list otherwise
    """
    return [agent for agent in agents if agent.agent_type.id == agent_id]


def get_all_instruction_files(target: Path, agents: list[DetectedAgent] | None = None) -> list[Path]:
    """
    Get all instruction files for all detected agents.

    Args:
        target: Project root to scan
        agents: Pre-detected agents (avoids redundant filesystem scan)

    Returns:
        Deduplicated list of all instruction file paths
    """
    all_files: set[Path] = set()

    for detected in agents if agents is not None else detect_agents(target):
        all_files.update(detected.instruction_files)
        all_files.update(detected.rule_files)

    return sorted(all_files)


def get_all_scannable_files(target: Path, agents: list[DetectedAgent] | None = None) -> list[Path]:
    """
    Get all files the regex engine should scan: instruction, rule, and config files.

    Config files (e.g. .claude/settings.json) are included so that rules with
    explicit paths.include targeting them can match.

    Args:
        target: Project root to scan
        agents: Pre-detected agents (avoids redundant filesystem scan)

    Returns:
        Deduplicated list of all scannable file paths
    """
    all_files: set[Path] = set()

    for detected in agents if agents is not None else detect_agents(target):
        all_files.update(detected.instruction_files)
        all_files.update(detected.rule_files)
        all_files.update(detected.config_files)

    return sorted(all_files)
