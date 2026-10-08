"""Which of an agent's hooks can intercept the file reads and writes heal makes.

A hook intercepts when it runs before a tool call and its matcher covers a file tool.
Which events do that, and which of the file tools each gates, is data in each agent's
`config.yml` (`intercept_events`): Claude, Codex and Antigravity write `PreToolUse`, Copilot
and Cursor `preToolUse`, and Cursor also gates reads with `beforeReadFile`. Event names compare
without regard to case, since Copilot reads either spelling.
"""

from __future__ import annotations

import re

from reporails_cli.core.platform.dto.results import AgentConfig, HookEntry

# The tools heal reads and writes files with; a hook on `MultiEdit` intercepts an edit.
HEAL_TOOLS: tuple[str, ...] = ("Read", "Edit", "Write")
_TOOL_NAMES: dict[str, str] = {"Read": "Read", "Edit": "Edit", "Write": "Write", "MultiEdit": "Edit"}

_PLAIN_MATCHER = re.compile(r"[A-Za-z0-9_|]+")


def _matches(matcher: str, tool: str) -> bool:
    """Whether `matcher` selects `tool`: a name or `a|b` list exactly, any other text as a pattern."""
    if _PLAIN_MATCHER.fullmatch(matcher):
        return tool in matcher.split("|")
    try:
        return re.search(matcher, tool) is not None
    except re.error:
        return False


def intercepted_tools(hook: HookEntry, config: AgentConfig) -> tuple[str, ...]:
    """The tools of Read, Edit and Write that `hook` can intercept; empty when it cannot intercept any.

    `config` is the hook's own agent: its `intercept_events` name the events that gate file tools.
    """
    gated = next(
        (tools for event, tools in config.intercept_events.items() if event.casefold() == hook.event.casefold()), ()
    )
    reachable = tuple(tool for tool in HEAL_TOOLS if tool in gated)
    if hook.matcher in ("", "*"):
        return reachable
    covered = {_TOOL_NAMES[name] for name in _TOOL_NAMES if _matches(hook.matcher, name)}
    return tuple(tool for tool in reachable if tool in covered)
