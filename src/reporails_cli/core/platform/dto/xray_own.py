"""The coding agent's own context as one group of an agent's "in context" list: the keys of its items, how the size
of the group was worked out, and the items with the measure of each share.

A value with no source is `None`, which reads as "not known here".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.events import HarnessKind

# What one row of an agent's "in context" list stands for.
ContextKey = Literal[
    "task",
    "source",
    "hooks",
    "builtin",
    "rest",
    "system_prompt",
    "tool_definitions",
    "tool_io",
    "skill_listing",
    "estimated",
    "conversation",
    "agent_listing",
    "deferred_tools",
    "session_context",
    "harness_other",
    "thinking",
    "built_in_rest",
    "definition",
]
# The row keys that are items of the coding agent's own context, in display order: the "in context" list shows them
# as one group, not as rows.
OWN_KEYS: tuple[ContextKey, ...] = (
    "built_in_rest",
    "system_prompt",
    "tool_definitions",
    "agent_listing",
    "skill_listing",
    "deferred_tools",
    "session_context",
    "thinking",
    "harness_other",
)
# The harness kind each listed item of the coding agent's own context is recorded as.
LISTED: dict[ContextKey, HarnessKind] = {
    "agent_listing": "agent_list",
    "skill_listing": "skill_list",
    "deferred_tools": "deferred_tools",
    "session_context": "session_context",
}
# The listings sized from their recorded characters when no request sizes them.
LISTING_KEYS: tuple[ContextKey, ...] = ("agent_listing", "deferred_tools", "session_context")
# How the size of the coding agent's own context was worked out: from the agent's own recorded request, from the
# latest complete request before its peak reply, or estimated with no recorded request.
OwnBasis = Literal["measured", "measured_earlier", "estimate"]
# Whether an item's text can be read in the transcript.
Visibility = Literal["hidden", "partial", "shown"]


@dataclass(frozen=True)
class XrayListed:
    """What a row's share leaves to another row: that row's label and tokens, and whether the row's text holds it
    (the system prompt's does; the other messages' does not)."""

    label: str
    tokens: int
    in_text: bool

    def to_json(self) -> JsonObject:
        """The record as a JSON object."""
        return {"label": self.label, "tokens": self.tokens, "in_text": self.in_text}


@dataclass(frozen=True)
class XrayRowMeasure:
    """How a measured row's share was worked out: the characters of the recorded request it comes from, the image
    tokens added to it, the tokens already shown in an earlier row and taken off, and what those tokens are, row by
    row."""

    chars: int
    images: int
    listed_above: int
    listed: tuple[XrayListed, ...] = ()

    def to_json(self) -> JsonObject:
        """The measure as a JSON object."""
        listed: list[JsonValue] = [item.to_json() for item in self.listed]
        return {"chars": self.chars, "images": self.images, "listed_above": self.listed_above, "listed": listed}


@dataclass(frozen=True)
class XrayOwnItem:
    """One item of the coding agent's own context: its key, label, what it holds, its size, how that size was worked
    out (None for an estimate), whether its text can be read in the transcript, whether a recorded request holds its
    text, for the system prompt how many different system prompts the agent's requests were sent with, how the
    item's own share was worked out, the tokens of the whole text the share is taken from, and what the item's
    characters hold beyond its readable text (None when all of them are readable)."""

    key: ContextKey
    label: str
    description: str | None
    tokens_est: int
    measure: XrayRowMeasure | None
    visible: Visibility
    has_text: bool
    shapes: int
    basis: OwnBasis
    whole_tokens: int
    unread: str | None

    def to_json(self) -> JsonObject:
        """The item as a JSON object."""
        return {
            "key": self.key,
            "label": self.label,
            "description": self.description,
            "tokens_est": self.tokens_est,
            "measure": None if self.measure is None else self.measure.to_json(),
            "visible": self.visible,
            "has_text": self.has_text,
            "shapes": self.shapes,
            "basis": self.basis,
            "whole_tokens": self.whole_tokens,
            "unread": self.unread,
        }


@dataclass(frozen=True)
class XrayOwnContext:
    """What the coding agent itself put in an agent's context: the group's label and reason, its size (the sum of its
    items, or what the estimates leave when no request was recorded), how the size was worked out, the recorded
    request it comes from with its tokens per character (None when none), and the items in display order."""

    label: str
    reason: str
    tokens_est: int
    basis: OwnBasis
    request_id: str | None
    tokens_per_char: float | None
    rows: tuple[XrayOwnItem, ...]

    def to_json(self) -> JsonObject:
        """The group as a JSON object."""
        rows: list[JsonValue] = [row.to_json() for row in self.rows]
        return {
            "label": self.label,
            "reason": self.reason,
            "tokens_est": self.tokens_est,
            "basis": self.basis,
            "request_id": self.request_id,
            "tokens_per_char": self.tokens_per_char,
            "rows": rows,
        }
