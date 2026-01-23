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


# Known coding agents and their conventions
KNOWN_AGENTS: dict[str, AgentType] = {
    "claude": AgentType(
        id="claude",
        name="Claude (Anthropic)",
        instruction_patterns=("CLAUDE.md", "**/CLAUDE.md"),
        config_patterns=(".claude/settings.json", ".claude/mcp.json"),
        rule_patterns=(".claude/rules/*.md", ".claude/**/*.md"),
    ),
    "cursor": AgentType(
        id="cursor",
        name="Cursor",
        instruction_patterns=(".cursorrules", ".cursor/rules/*.md"),
        config_patterns=(".cursor/settings.json",),
        rule_patterns=(".cursor/rules/*.md",),
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


def detect_agents(target: Path) -> list[DetectedAgent]:
    """
    Detect which coding agents are configured in the target directory.

    Scans for known file patterns and returns detected agents with their files.

    Args:
        target: Project root to scan

    Returns:
        List of detected agents with their associated files
    """
    detected: list[DetectedAgent] = []

    for _agent_id, agent_type in KNOWN_AGENTS.items():
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

        # Only include if we found at least one instruction file
        if instruction_files:
            detected.append(
                DetectedAgent(
                    agent_type=agent_type,
                    instruction_files=sorted(set(instruction_files)),
                    config_files=sorted(set(config_files)),
                    rule_files=sorted(set(rule_files)),
                )
            )

    return detected


def get_all_instruction_files(target: Path) -> list[Path]:
    """
    Get all instruction files for all detected agents.

    Args:
        target: Project root to scan

    Returns:
        Deduplicated list of all instruction file paths
    """
    all_files: set[Path] = set()

    for detected in detect_agents(target):
        all_files.update(detected.instruction_files)
        all_files.update(detected.rule_files)

    return sorted(all_files)
