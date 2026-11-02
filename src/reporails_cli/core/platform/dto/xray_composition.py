"""What one agent's context is made of at each reply: an exact total split into estimated categories.

The total and the cache split of a reply are exact; every category but the remainder is an estimate, and the
remainder is what the total leaves, so the categories always add up to the total.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, get_args

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue

CompositionKey = Literal[
    "system_tools",
    "instructions",
    "rules_skills",
    "skill_listing",
    "memory",
    "hook_notes",
    "conversation",
    "tool_results",
]

# The categories in the order a reply's row lists them.
COMPOSITION_KEYS: tuple[CompositionKey, ...] = get_args(CompositionKey)

# The category that takes what the estimates leave of the total.
REMAINDER_KEY: CompositionKey = "system_tools"

# The categories that are estimated, in row order.
ESTIMATED_KEYS: tuple[CompositionKey, ...] = tuple(key for key in COMPOSITION_KEYS if key != REMAINDER_KEY)


@dataclass(frozen=True)
class XrayCompositionLabel:
    """One category's key and the name the page shows it by."""

    key: CompositionKey
    label: str


@dataclass(frozen=True)
class ReplyComposition:
    """One reply: when, its exact context total and cache split, its categories in `COMPOSITION_KEYS` order and
    whether the estimates overshoot the total (the remainder is then negative)."""

    t: float
    total: int
    input_tokens: int
    cache_write: int
    cache_read: int
    parts: tuple[int, ...]
    over_estimate: bool

    def to_row(self) -> list[JsonValue]:
        """The reply as one row of the composition's columns."""
        return [
            self.t,
            self.total,
            self.input_tokens,
            self.cache_write,
            self.cache_read,
            *self.parts,
            self.over_estimate,
        ]


@dataclass(frozen=True)
class XrayComposition:
    """An agent's replies as rows, one per reply, and the index of the reply with the highest context."""

    replies: tuple[ReplyComposition, ...]
    peak: int | None

    def to_json(self) -> JsonObject:
        """The composition as columns: the category keys, one row per reply and the peak index."""
        rows: list[JsonValue] = [reply.to_row() for reply in self.replies]
        keys: list[JsonValue] = list(COMPOSITION_KEYS)
        return {"keys": keys, "replies": rows, "peak": self.peak}
