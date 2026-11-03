"""What one agent's context is made of at each reply: an exact total split into estimated categories.

The total and the cache split of a reply are exact; every category but the remainder is an estimate, and the
remainder is what the total leaves, so the categories always add up to the total.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, get_args

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.events import RequestSize, TokenUsage

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

# The categories that hold what was said and what the tools returned.
SPOKEN_KEYS: tuple[CompositionKey, ...] = ("conversation", "tool_results")


@dataclass(frozen=True)
class RequestMeasure:
    """A recorded request and what scales it to the exact total of the reply it answered: `scale`, the tokens per
    character of its text (images left out), and the tokens of its images at its model's tier, `images` in the
    conversation and `result_images` inside tool results."""

    size: RequestSize
    scale: float
    images: int
    result_images: int


@dataclass(frozen=True)
class CarriedReply:
    """One reply's usage and the estimated tokens each source (by source id) carried in its context."""

    usage: TokenUsage
    by_source: dict[str, int]


@dataclass(frozen=True)
class XrayCompositionLabel:
    """One category's key and the name the page shows it by."""

    key: CompositionKey
    label: str


@dataclass(frozen=True)
class ReplyComposition:
    """One reply: when, its exact context total and cache split, its categories in `COMPOSITION_KEYS` order and
    whether the estimates overshoot the total (the remainder is then negative). A measured reply was split by the
    request Claude Code recorded for it (`measure`, set only for a request with no unresolved message), so its
    parts add up to the total with no remainder."""

    t: float
    total: int
    input_tokens: int
    cache_write: int
    cache_read: int
    parts: tuple[int, ...]
    over_estimate: bool
    measure: RequestMeasure | None

    @property
    def measured(self) -> bool:
        """Whether the reply was split by its recorded request."""
        return self.measure is not None

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
            self.measured,
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
