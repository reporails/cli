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

# A matcher made only of these characters names tools exactly, `|` or `,` between them.
_NAME_LIST_MATCHER = re.compile(r"[A-Za-z0-9_\- ,|]+")
_LIST_SEPARATOR = re.compile(r"\s*[|,]\s*")


def matcher_selects(matcher: str, tool: str) -> bool:
    """Whether a hook registered under `matcher` runs for the tool (or source) named `tool`, as Claude Code reads a
    matcher: empty or `*` selects every name; letters, digits, `_`, `-`, spaces, `,` and `|` only is an exact name or
    a list of exact names; anything else is an unanchored regular expression, one that does not compile selecting
    nothing. https://code.claude.com/docs/en/hooks"""
    if matcher in ("", "*"):
        return True
    if _NAME_LIST_MATCHER.fullmatch(matcher):
        return tool in _LIST_SEPARATOR.split(matcher.strip())
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
    covered = {edit for name, edit in _TOOL_NAMES.items() if matcher_selects(hook.matcher, name)}
    return tuple(tool for tool in reachable if tool in covered)
