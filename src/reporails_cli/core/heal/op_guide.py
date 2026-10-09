"""One plain instruction per rewrite op, for the lines of a plan that need a decision."""

from __future__ import annotations

_CHANGE_THIS_LINE = "Make the stated change on this line only."

OP_GUIDE: dict[str, str] = {
    "elaborate": (
        "Add the object this instruction acts on, using only words from its own section; "
        "add no clause, condition or reason."
    ),
    "category": (
        "State what this prohibition forbids as a category, and keep it directly after the directive it limits."
    ),
    "keep-cut": "Delete this line if it says nothing its partner does not; otherwise leave it unchanged.",
    "name": "Name, in backticks, the tool, file or command this line already refers to; add nothing else.",
    "scope": "Replace the broad condition with the specific situation it means, or drop the condition.",
    "charge": "Make this line either a clear instruction or a plain description.",
    "split": "Give each instruction its own sentence; where a piece says it or them, repeat the noun it stands for.",
    "rewrite": "Change only this line so the rule's Fail example no longer describes it.",
    "hoist": "Move this line into the file named by the plan and delete the partner's copy; change no words.",
    "direct": _CHANGE_THIS_LINE,
    "move": _CHANGE_THIS_LINE,
    "negation-form": _CHANGE_THIS_LINE,
    "unbold": _CHANGE_THIS_LINE,
    "italic": _CHANGE_THIS_LINE,
    "code": _CHANGE_THIS_LINE,
    "dedupe": _CHANGE_THIS_LINE,
}

# The ops whose guide lets the line leave its file: `dedupe` and `keep-cut` delete it, `hoist` moves it away.
LINE_LEAVING_OPS: frozenset[str] = frozenset({"dedupe", "keep-cut", "hoist"})


CHANGE_GUIDE: dict[str, str] = {
    "split-keep-lead-in": (
        "Keep the lead-in with every item: repeat it in each sentence you make, or leave the sentence whole."
    ),
    "split-repeat": (
        "Give each instruction its own sentence, repeating the object named after `split-repeat:` only in an "
        "instruction that acts on it; add no other word, and leave the sentence whole if a piece would change "
        "its meaning."
    ),
    "split-series": "Give every item of the list its own sentence with its verb repeated, or leave the sentence whole.",
    "split-keep-condition": "Repeat the condition in each sentence it limits, or leave the sentence whole.",
    "split-keep-sequence": "Keep a step that starts with then in one sentence with the step before it.",
}


def change_lines(changes: set[str] | frozenset[str]) -> dict[str, str]:
    """The guide line of each kind of change in `changes` (a code, with any `:<object>` part ignored), in
    name order."""
    kinds = {c.partition(":")[0] for c in changes}
    return {kind: CHANGE_GUIDE[kind] for kind in sorted(kinds) if kind in CHANGE_GUIDE}


def op_lines(ops: set[str] | frozenset[str]) -> dict[str, str]:
    """The guide line of each op in `ops`, in name order; an op with no entry reads as the generic line."""
    return {op: OP_GUIDE.get(op, _CHANGE_THIS_LINE) for op in sorted(ops)}
