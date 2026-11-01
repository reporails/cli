"""What each coding agent calls things: the labels, colours and icons the page draws a session with."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from reporails_cli.core.platform.dto.xray import (
    AdapterVocabulary,
    FactKind,
    XrayAgentTypeInfo,
    XrayCategoryInfo,
    XrayNesting,
    XrayNodeKindInfo,
    XrayRoot,
    XraySourceKindInfo,
    XrayTriggerInfo,
)

# Colours handed to the agent types found on disk, in order, cycling.
DISK_TYPE_COLOURS = ("#7FD4A8", "#E8C27A", "#5FC4E8", "#C9A0F0", "#D4B483", "#8FB8A8", "#E89AB8", "#B8C77F")

_GENERIC_ICON = "M5 5h14v14H5z M9 10h6 M9 14h4"
_MAIN_ICON = "M4 6l5 6l-5 6 M12 18h8"
_EXPLORE_ICON = "M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14z M20 20l-4-4"
_GENERAL_ICON = "M12 3v6 M12 15v6 M3 12h6 M15 12h6"
_PLAN_ICON = "M9 3h6 M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3"
_FORK_ICON = "M2 12s4-7 10-7s10 7 10 7s-4 7-10 7S2 12 2 12z M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6z"

_CLAUDE_SOURCE_KINDS = (
    XraySourceKindInfo("instructions", "Instructions", "I", False),
    XraySourceKindInfo("rule", "Rules", "R", False),
    XraySourceKindInfo("skill", "Skills", "S", False),
    XraySourceKindInfo("memory", "Memory", "M", False),
    XraySourceKindInfo("mcp", "MCP servers", "C", False),
    XraySourceKindInfo("hook", "Hooks", "H", False),
)

_CLAUDE_AGENT_TYPES = (
    XrayAgentTypeInfo("main", "main", "#6EA8FF", _MAIN_ICON),
    XrayAgentTypeInfo("Explore", "explore", "#4FC7B5", _EXPLORE_ICON),
    XrayAgentTypeInfo("general-purpose", "general", "#A594FF", _GENERAL_ICON),
    XrayAgentTypeInfo("Plan", "plan", "#E8B04E", _PLAN_ICON),
    XrayAgentTypeInfo("fork", "fork", "#EE7FA6", _FORK_ICON),
)

_CLAUDE_CATEGORIES = (
    XrayCategoryInfo("read", "Read", True),
    XrayCategoryInfo("edit", "Edit", True),
    XrayCategoryInfo("run", "Bash", True),
    XrayCategoryInfo("mcp", "MCP", False),
    XrayCategoryInfo("agent", "Agents", False),
    XrayCategoryInfo("other", "Other", False),
)

_CLAUDE_TRIGGERS = (
    XrayTriggerInfo("session_start", "loaded with the session's instructions"),
    XrayTriggerInfo("path_match", "loaded when a matching file was touched"),
    XrayTriggerInfo("agent", "loaded by the agent"),
    XrayTriggerInfo("inherited", "handed down at launch"),
    XrayTriggerInfo("hook", "added by a hook"),
)

_CLAUDE_FACT_NOTES: dict[FactKind, str] = {
    "memory_unlinked": "{count} not linked",
    "repeated_instructions": "in {contexts} contexts",
    "kind_absent": "No {label} configured",
}


def _claude(disk_types: Sequence[str]) -> AdapterVocabulary:
    """Claude Code's vocabulary, with each agent type found on disk after the built-in ones."""
    known = {item.key for item in _CLAUDE_AGENT_TYPES}
    extra = [name for name in dict.fromkeys(disk_types) if name not in known]
    found = tuple(
        XrayAgentTypeInfo(name, name, DISK_TYPE_COLOURS[number % len(DISK_TYPE_COLOURS)], _GENERIC_ICON)
        for number, name in enumerate(extra)
    )
    return AdapterVocabulary(
        tool="Claude Code",
        root=XrayRoot("main", "main agent"),
        source_kinds=_CLAUDE_SOURCE_KINDS,
        agent_types=(*_CLAUDE_AGENT_TYPES, *found),
        node_kinds=(XrayNodeKindInfo("agent", "Agent", True, True),),
        categories=_CLAUDE_CATEGORIES,
        nesting=XrayNesting(True, None),
        triggers=_CLAUDE_TRIGGERS,
        fact_notes=_CLAUDE_FACT_NOTES,
    )


# The vocabulary of each coding agent, by the agent's name.
VOCABULARIES: dict[str, Callable[[Sequence[str]], AdapterVocabulary]] = {"claude": _claude}


def vocabulary_for(agent: str, disk_types: Sequence[str]) -> AdapterVocabulary:
    """The vocabulary of coding agent `agent`, with the agent types found on disk (`disk_types`) after its
    built-in ones; raises `ValueError` for an agent with no vocabulary."""
    build = VOCABULARIES.get(agent)
    if build is None:
        raise ValueError(f"no x-ray vocabulary for agent {agent!r}")
    return build(disk_types)
