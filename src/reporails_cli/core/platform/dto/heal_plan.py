"""Plan of one heal run: the text changes a script makes and the spots left to a rewrite."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, TypeGuard, get_args

# The operations a finding asks of a heal run; the order is the order of the guide that describes each.
HealOp = Literal[
    "elaborate",
    "category",
    "keep-cut",
    "name",
    "scope",
    "charge",
    "split",
    "rewrite",
    "hoist",
    "direct",
    "move",
    "negation-form",
    "unbold",
    "italic",
    "code",
    "dedupe",
]
_HEAL_OPS: frozenset[HealOp] = frozenset(get_args(HealOp))

# Ops a script can carry out; every other op is a slot.
SCRIPTABLE_OPS: frozenset[HealOp] = frozenset(
    {"split", "direct", "negation-form", "move", "unbold", "italic", "code", "dedupe"}
)
# Scriptable ops that rewrite the text of their own line in place: a second one on a line the first rewrote
# folds into that edit.
IN_PLACE_OPS: frozenset[HealOp] = frozenset({"direct", "negation-form", "unbold", "italic", "code"})
# The ops whose guide lets the line leave its file: `dedupe` and `keep-cut` delete it, `hoist` moves it away.
LINE_LEAVING_OPS: frozenset[HealOp] = frozenset({"dedupe", "keep-cut", "hoist"})
# The in-place ops that change the words of a line; on one line they run before the formatting ops.
WORD_CHANGING_OPS: frozenset[HealOp] = frozenset({"direct", "negation-form"})


def is_heal_op(value: object) -> TypeGuard[HealOp]:
    """Whether `value`, read from a reply, is one of the heal ops."""
    return value in _HEAL_OPS


# The op a deviation is about: a heal op, or `outside` for a change on a line the plan does not carry.
DeviationOp = HealOp | Literal["outside"]


@dataclass(frozen=True)
class PlanOp:
    """One finding's operation: rule, coordinate, op and what the result must show.

    `pi` is the atom's position index on its line; None addresses every atom of the line.
    `expect` holds `{"after": [file, line, pi]}` for a move and `{"keep": [file, line]}` for a
    dedupe or keep-cut.
    """

    rule: str
    file: str
    line: int
    pi: int | None
    op: HealOp
    expect: dict[str, list[object]] = field(default_factory=dict)


@dataclass(frozen=True)
class Folded:
    """An in-place op folded into the edit of its line: its op, rule and the place of its atom on the line."""

    op: HealOp
    rule: str
    nth: int | None = None


@dataclass(frozen=True)
class Edit:
    """An exact text change at one line (or the lines `before` spans, joined by newlines).

    `after` is None when the lines are removed; `move_after` then names the line of the file the
    removed line is placed directly after (a move), or is None (a deletion). `nth` is the place of the atom
    the op addressed among its line's atoms, first is 0 (None: every atom of the line); `folded` holds the
    later in-place ops of the same line that `after` also carries.
    """

    file: str
    line: int
    before: str
    after: str | None
    op: HealOp
    rule: str
    move_after: int | None = None
    nth: int | None = None
    folded: tuple[Folded, ...] = ()

    @property
    def ops(self) -> tuple[Folded, ...]:
        """Every op the edit carries: its own first, then each folded into it."""
        return (Folded(self.op, self.rule, self.nth), *self.folded)

    @property
    def span(self) -> int:
        """How many file lines `before` covers."""
        return self.before.count("\n") + 1


@dataclass(frozen=True)
class Slot:
    """A spot a rewrite fills, bound to its line or its section.

    `change` is the one change a refused split allows (`split-keep-lead-in`, `split-repeat:<object>`,
    `split-series`, `split-keep-condition`, `split-keep-sequence`); empty for any other slot."""

    file: str
    line: int
    pi: int | None
    op: HealOp
    rule: str
    text: str
    bound: Literal["line", "section"]
    change: str = ""


@dataclass(frozen=True)
class Refusal:
    """An op the plan does not carry, with the reason as a short code."""

    op: PlanOp
    reason: str


@dataclass(frozen=True)
class Plan:
    """The edits a script applies, the slots a rewrite fills and the ops refused."""

    edits: tuple[Edit, ...] = ()
    slots: tuple[Slot, ...] = ()
    refused: tuple[Refusal, ...] = ()


@dataclass(frozen=True)
class Deviation:
    """Where a rewritten file departs from its plan, as short codes."""

    file: str
    line: int
    op: DeviationOp
    rule: str
    expected: str
    found: str
