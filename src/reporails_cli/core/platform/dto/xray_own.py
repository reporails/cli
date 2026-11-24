"""The coding agent's own context as one group of an agent's "in context" list: the keys of its items, how the size
of the group was worked out, and the items with the measure of each share.

A value with no source is `None`, which reads as "not known here".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue

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
]
# The row keys that are items of the coding agent's own context, in display order: the "in context" list shows them
# as one group, not as rows.
OWN_KEYS: tuple[ContextKey, ...] = (
    "system_prompt",
    "tool_definitions",
    "agent_listing",
    "skill_listing",
    "deferred_tools",
    "session_context",
    "thinking",
    "harness_other",
)
# The listings sized from their recorded characters when no request sizes them.
LISTING_KEYS: tuple[ContextKey, ...] = ("agent_listing", "deferred_tools", "session_context")
# How the size of the coding agent's own context was worked out: from the agent's own recorded request, from the
# latest complete request before its peak reply, or estimated with no recorded request.
OwnBasis = Literal["measured", "measured_earlier", "estimate"]
# Whether an item's text can be read in the transcript.
Visibility = Literal["hidden", "partial", "shown"]


@dataclass(frozen=True)
class XrayRowMeasure:
    """How a measured row's share was worked out: the characters of the recorded request it comes from, the image
    tokens added to it and the tokens already shown in an earlier row and taken off."""

    chars: int
    images: int
    listed_above: int

    def to_json(self) -> JsonObject:
        """The measure as a JSON object."""
        return {"chars": self.chars, "images": self.images, "listed_above": self.listed_above}


@dataclass(frozen=True)
class XrayOwnItem:
    """One item of the coding agent's own context: its key, label, what it holds, its size, how that size was worked
    out (None for an estimate), whether its text can be read in the transcript, whether a recorded request holds its
    text and, for the system prompt, how many different system prompts the agent's requests were sent with."""

    key: ContextKey
    label: str
    description: str | None
    tokens_est: int
    measure: XrayRowMeasure | None
    visible: Visibility
    has_text: bool
    shapes: int

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
