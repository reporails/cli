"""Scripted edits for the plan ops that change punctuation, case, emphasis, order or presence only.

Each function takes the op, the atoms of its file and the file's lines, and returns the one `Edit` it
makes, or None when it cannot apply safely (the op then becomes a slot). No function adds, drops or
changes a word, except the named swaps (`Never` to `Do not`, a dropped hedge).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Sequence
from functools import partial
from itertools import pairwise

from reporails_cli.core.heal.mechanical_fixers import (
    MechanicalFix,
    fix_bold_on_constraints,
    fix_italic_constraints,
    fix_unformatted_code,
)
from reporails_cli.core.heal.preservation.conditions import conditional
from reporails_cli.core.heal.preservation.fragments import leaves_fragment
from reporails_cli.core.lint.client_checks import running_sentences
from reporails_cli.core.mapper.classify import HEDGE_LEADS, hedges_with_should
from reporails_cli.core.mapper.instructions import holds_comma_series, opens_command, without_joining_word
from reporails_cli.core.mapper.md_parser import code_spans, emphasis_runs, link_spans
from reporails_cli.core.mapper.structure import in_any_span, paragraph_lines, read_structure
from reporails_cli.core.platform.dto.heal_plan import Edit, PlanOp
from reporails_cli.core.platform.dto.ruleset import Atom

# The joint between two instructions the mapper cut apart: a mark (or spaced dash) and a joining `and` it left behind.
_JOINT_TAIL_RE = re.compile(r"(?:\s*[\u2014\u2013;,]|\s-)\s*(?:and\s+)?$", re.IGNORECASE)
_SENTENCE_MARK_RE = re.compile(r"[.!?][)\]\"'`*_]*$")
_NEVER_RE = re.compile(r"(Never|never)\b(?=\s+\S)")
_HEDGE_WORDS = (HEDGE_LEADS - {"prefer", "preferably", "consider", "try"}) | {"please"}
_HEDGE_RE = re.compile(
    rf"(?:you\s+should|try\s+to|(?:{'|'.join(sorted(_HEDGE_WORDS))})\b,?)\s+",
    re.IGNORECASE,
)
_RUNNING_FORMATS = frozenset({"prose", "list", "numbered"})


def _body(line: str) -> str:
    return line.rstrip("\r\n")


def _keepends(lines: Sequence[str]) -> list[str]:
    """A copy of `lines` with a newline on each, the form the line fixers read."""
    return [_body(line) + "\n" for line in lines]


def atoms_at(atoms: Sequence[Atom], line: int, pi: int | None) -> list[Atom]:
    """The atoms of `line`, narrowed to position index `pi` when given."""
    return [a for a in atoms if a.line == line and (pi is None or a.position_index == pi)]


def _upper_first(text: str) -> str | None:
    """`text` with its first letter upper-cased (leading emphasis marks skipped); None when it opens otherwise."""
    i = 0
    while i < len(text) and text[i] in "*_":
        i += 1
    if i >= len(text) or not text[i].isalpha():
        return None
    return text[:i] + text[i].upper() + text[i + 1 :]


# ── split ───────────────────────────────────────────────────────────────


def _packed_sentences(atoms: Sequence[Atom], op: PlanOp) -> list[list[Atom]] | None:
    """The sentences on the op's line that hold more than one instruction atom, in order (the op's own when it
    names a position); None when there are none, or one runs past the line, is a lead-in or is not running text."""
    held = [
        s
        for s in running_sentences(list(atoms))
        if len(s) >= 2 and any(a.line == op.line and (op.pi is None or a.position_index == op.pi) for a in s)
    ]
    if not held or any(a.line != op.line or a.lead_in or a.format not in _RUNNING_FORMATS for s in held for a in s):
        return None
    return held


def _stands_alone(sentence: Sequence[Atom]) -> bool:
    """Whether every atom of the sentence is a charged instruction with its own predicate and no object it
    shares with a sibling."""
    if any(a.charge_value == 0 or a.slots is None or a.slots.predicate_span is None for a in sentence):
        return False
    objects = [a.slots.object_span is not None for a in sentence if a.slots is not None]
    return all(objects) or not any(objects)


def _starts(content: str, sentences: Sequence[Sequence[Atom]]) -> list[int] | None:
    """Where each atom of the sentences starts in the line, in order; None when one is not found."""
    starts, cursor = [], 0
    for atom in (a for s in sentences for a in s):
        start = _atom_start(content, atom, cursor)
        if start is None:
            return None
        starts.append(start)
        cursor = start + 1
    return starts


def _cut_at(content: str, start: int) -> tuple[str, int, int] | None:
    """`content` with the joint before the atom at `start` turned into a full stop; also how many emphasis
    runs it reopened and how many joining `and` it dropped. None when no joint mark ends the text before
    `start`, or the joint lies in code or a link."""
    joint = _JOINT_TAIL_RE.search(content[:start])
    if joint is None or content[start - 1] in "*_":
        return None
    head = content[: joint.start()].rstrip()
    protected = [(s.start, s.end) for s in code_spans(content)] + list(link_spans(content))
    if not head or in_any_span(joint.start(), protected) or in_any_span(start, protected):
        return None
    spanning = [r for r in emphasis_runs(content) if r.content_start <= joint.start() and start < r.content_end]
    spanning.sort(key=lambda r: (r.start, -r.end))
    stop = "" if _SENTENCE_MARK_RE.search(head) else "."
    closers = "".join(r.marker for r in reversed(spanning))
    openers = "".join(r.marker for r in spanning)
    rest = without_joining_word(content[start:])
    tail = _upper_first(rest)
    if tail is None:
        return None
    dropped = int(joint.group().strip().lower().endswith("and")) + int(rest != content[start:])
    return f"{head}{stop}{closers} {openers}{tail}", len(spanning), dropped


def _offsets(sentences: Sequence[Sequence[Atom]]) -> list[int]:
    """Where each sentence's first atom sits among the atoms of all the sentences."""
    return [sum(len(s) for s in sentences[:i]) for i in range(len(sentences))]


def _only_joints_dropped(before: str, after: str, dropped: int) -> bool:
    """Whether `after` holds the words of `before` but for `dropped` joining `and`."""
    words = Counter(re.findall(r"\w+", before.lower())) - Counter({"and": dropped})
    return words == Counter(re.findall(r"\w+", after.lower()))


def _scoped(atom: Atom) -> bool:
    """Whether the mapper read a scope for the atom."""
    return atom.slots is not None and atom.slots.scope_span is not None


def _detaches(before: Atom, piece: Atom) -> bool:
    """Whether cutting `piece` off `before` leaves it without a condition `before` sets: `before` holds a
    scope or a condition the piece lacks, and the piece is the other polarity (a fallback to a prohibition
    bounded by a condition, not one more rule beside it)."""
    if _scoped(before) and not _scoped(piece):
        return True
    return before.charge_value != piece.charge_value and conditional(before) and not conditional(piece)


def _cuts_series(content: str, sentence: Sequence[Atom], starts: Sequence[int]) -> bool:
    """Whether a cut of the sentence falls at a comma after an atom that holds a comma series of its own
    (`read it, classify it, and write it`): the first sentence would end on part of its series."""
    for k in range(1, len(sentence)):
        joint = _JOINT_TAIL_RE.search(content[: starts[k]])
        if joint is not None and "," in joint.group() and holds_comma_series(content[starts[k - 1] : joint.start()]):
            return True
    return False


def _keeps_whole(content: str, sentences: Sequence[Sequence[Atom]], starts: Sequence[int]) -> bool:
    """Whether no cut ends a series partway or separates a piece from the condition the atom before it sets."""
    for sentence, at in zip(sentences, _offsets(sentences), strict=True):
        if _cuts_series(content, sentence, starts[at : at + len(sentence)]):
            return False
        if any(_detaches(a, b) for a, b in pairwise(sentence)):
            return False
    return True


def split(op: PlanOp, atoms: Sequence[Atom], lines: Sequence[str]) -> Edit | None:
    """Give each instruction atom of a packed sentence its own sentence, cut where the mapper cut it.

    None unless every atom of each packed sentence on the line is a charged instruction with its own
    predicate and no object shared with a sibling, no such sentence is a lead-in, and a joint mark ends the
    text before each cut.
    """
    sentences = _packed_sentences(atoms, op)
    if sentences is None or not all(_stands_alone(s) for s in sentences) or not 0 < op.line <= len(lines):
        return None
    content = _body(lines[op.line - 1])
    starts = _starts(content, sentences)
    if starts is None or not _keeps_whole(content, sentences, starts):
        return None
    cuts = [
        c
        for sentence, at in zip(sentences, _offsets(sentences), strict=True)
        for c in starts[at + 1 : at + len(sentence)]
    ]
    text, reopened, dropped = content, 0, 0
    for start in reversed(cuts):
        cut = _cut_at(text, start)
        if cut is None:
            return None
        text, more, gone = cut
        reopened += more
        dropped += gone
    if (
        not _only_joints_dropped(content, text, dropped)
        or len(emphasis_runs(text)) != len(emphasis_runs(content)) + reopened
        or leaves_fragment(content, text)
    ):
        return None
    return Edit(op.file, op.line, content, text, op.op, op.rule)


# ── direct / negation-form ──────────────────────────────────────────────


def _atom_start(content: str, atom: Atom, after: int = 0) -> int | None:
    """Where the atom's text starts in the line at or past `after` (past opening emphasis marks, which the
    mapper re-wraps per atom); None when not found or in code."""
    at = content.find(atom.text.strip().strip("*_"), after)
    if at < 0 or in_any_span(at, [(s.start, s.end) for s in code_spans(content)]):
        return None
    return at


def _single_target(atoms: Sequence[Atom], op: PlanOp, lines: Sequence[str]) -> tuple[Atom, str, int] | None:
    found = atoms_at(atoms, op.line, op.pi)
    if len(found) != 1 or not 0 < op.line <= len(lines):
        return None
    content = _body(lines[op.line - 1])
    start = _atom_start(content, found[0])
    return None if start is None else (found[0], content, start)


def negation_form(op: PlanOp, atoms: Sequence[Atom], lines: Sequence[str]) -> Edit | None:
    """`Never …` to `Do not …`, also inside a leading emphasis run; None for any other opening."""
    target = _single_target(atoms, op, lines)
    if target is None:
        return None
    _, content, start = target
    m = _NEVER_RE.match(content, start)
    if m is None or not opens_command(content[start:]):
        return None
    swap = "Do not" if m.group(1) == "Never" else "do not"
    after = content[:start] + swap + content[m.end() :]
    return Edit(op.file, op.line, content, after, op.op, op.rule)


def direct(op: PlanOp, atoms: Sequence[Atom], lines: Sequence[str]) -> Edit | None:
    """Drop a leading hedge (`try to`, `ideally,`, `perhaps`, `maybe`, `please`) or `you should` before a command.

    `prefer` and `consider` change what is asked, so they are left to a rewrite.
    """
    target = _single_target(atoms, op, lines)
    if target is None:
        return None
    _, content, start = target
    m = _HEDGE_RE.match(content, start)
    if m is None:
        return None
    if m.group().lower().startswith("you") and not hedges_with_should(content[start:]):
        return None
    rest = content[m.end() :]
    if not opens_command(rest):
        return None
    if content[start].isupper():
        rest = _upper_first(rest) or ""
    if not rest:
        return None
    return Edit(op.file, op.line, content, content[:start] + rest, op.op, op.rule)


# ── move / dedupe ───────────────────────────────────────────────────────


def _whole_line_atom(atoms: Sequence[Atom], line: int) -> Atom | None:
    """The one atom of `line` when it is the only one there and not a heading; else None."""
    found = [a for a in atoms if a.line == line]
    if len(found) != 1 or found[0].kind == "heading" or found[0].lead_in:
        return None
    return found[0]


def _moves_within_one_block(atoms: Sequence[Atom], lines: Sequence[str], target: int, anchor: int) -> bool:
    """Whether the lines `target` and `anchor` sit in one paragraph, or in one list at one depth with only
    items of that depth between them and after each of them."""
    content = "".join(_keepends(lines))
    if any(lo + 1 <= target <= hi + 1 and lo + 1 <= anchor <= hi + 1 for lo, hi in paragraph_lines(content)):
        return True
    first, last = _whole_line_atom(atoms, target), _whole_line_atom(atoms, anchor)
    if first is None or last is None or first.format not in ("list", "numbered") or first.list_depth != last.list_depth:
        return False
    items = dict(read_structure(content).list_items)
    probe = {*range(min(target, anchor), max(target, anchor) + 1), target + 1, anchor + 1}
    for n in probe:
        if n > len(lines):
            continue
        here = [a for a in atoms if a.line == n]
        if n not in items or not here or any(a.list_depth != first.list_depth for a in here):
            return False
    return items.get(target) == items.get(anchor)


def move(op: PlanOp, atoms: Sequence[Atom], lines: Sequence[str]) -> Edit | None:
    """Move a whole single-atom line to directly after the line `expect["after"]` names, in one block."""
    after = op.expect.get("after")
    if not after or after[0] != op.file or not isinstance(after[1], int):
        return None
    anchor = after[1]
    if anchor == op.line or anchor == op.line - 1 or not 0 < anchor <= len(lines) or not 0 < op.line <= len(lines):
        return None
    if _whole_line_atom(atoms, op.line) is None or _whole_line_atom(atoms, anchor) is None:
        return None
    if not _moves_within_one_block(atoms, lines, op.line, anchor):
        return None
    return Edit(op.file, op.line, _body(lines[op.line - 1]), None, op.op, op.rule, move_after=anchor)


def _named(atom: Atom) -> frozenset[str]:
    return frozenset(t.strip("`") for t in atom.named_tokens)


def _paragraph_line_removal(op: PlanOp, lines: Sequence[str]) -> Edit | None:
    """The removal of a one-line paragraph, with one blank line beside it so no double blank is left."""
    content = "".join(_keepends(lines))
    if not any(lo + 1 == hi + 1 == op.line for lo, hi in paragraph_lines(content)):
        return None
    body = _body(lines[op.line - 1])
    if op.line < len(lines) and not _body(lines[op.line]).strip():
        return Edit(op.file, op.line, body + "\n" + _body(lines[op.line]), None, op.op, op.rule)
    if op.line > 1 and not _body(lines[op.line - 2]).strip():
        return Edit(op.file, op.line - 1, _body(lines[op.line - 2]) + "\n" + body, None, op.op, op.rule)
    return Edit(op.file, op.line, body, None, op.op, op.rule)


def dedupe(op: PlanOp, atoms: Sequence[Atom], lines: Sequence[str], partner: Atom | None = None) -> Edit | None:
    """Delete the target's whole line when it is the line's only atom and names the same backticked tokens as
    its partner; a paragraph line also takes one blank line beside it."""
    atom = _whole_line_atom(atoms, op.line)
    if atom is None or partner is None or not 0 < op.line <= len(lines) or atom.format not in _RUNNING_FORMATS:
        return None
    if not _named(atom) or _named(atom) != _named(partner):
        return None
    if atom.format == "prose":
        return _paragraph_line_removal(op, lines)
    return Edit(op.file, op.line, _body(lines[op.line - 1]), None, op.op, op.rule)


# ── italic / unbold / code ──────────────────────────────────────────────

_Fixer = Callable[[list[Atom], list[str]], list[MechanicalFix]]


def _through_fixer(fixer: _Fixer, op: PlanOp, atoms: Sequence[Atom], lines: Sequence[str]) -> Edit | None:
    """The edit an existing line fixer makes for the one atom the op names; None when its guard refuses it."""
    found = atoms_at(atoms, op.line, op.pi)
    if len(found) != 1 or not 0 < op.line <= len(lines):
        return None
    target = found[0]
    scope = [target]
    if fixer is fix_unformatted_code:  # the file's backticked words decide which names are code
        scope = [
            a if a is target else a.model_copy(update={"unformatted_code": []})
            for a in atoms
            if a.named_tokens or a is target
        ]
    fixes = [f for f in fixer(scope, _keepends(lines)) if f.line == op.line]
    if len(fixes) != 1 or fixes[0].before == fixes[0].after:
        return None
    fix = fixes[0]
    expected = "\n".join(_body(line) for line in lines[op.line - 1 : op.line - 1 + fix.before.count("\n") + 1])
    if fix.before != expected.rstrip():
        return None
    return Edit(op.file, op.line, fix.before, fix.after, op.op, op.rule)


def italic(op: PlanOp, atoms: Sequence[Atom], lines: Sequence[str]) -> Edit | None:
    """Wrap the constraint's sentence in italic, through the existing italic fixer."""
    return _through_fixer(fix_italic_constraints, op, atoms, lines)


def unbold(op: PlanOp, atoms: Sequence[Atom], lines: Sequence[str]) -> Edit | None:
    """Turn the bold terms of the atom the op names into italic, whatever its charge, through the bold fixer."""
    return _through_fixer(partial(fix_bold_on_constraints, any_charge=True), op, atoms, lines)


def code(op: PlanOp, atoms: Sequence[Atom], lines: Sequence[str]) -> Edit | None:
    """Wrap the atom's unformatted code tokens in backticks, through the existing code fixer."""
    return _through_fixer(fix_unformatted_code, op, atoms, lines)


TRANSFORMS: dict[str, Callable[..., Edit | None]] = {
    "split": split,
    "direct": direct,
    "negation-form": negation_form,
    "move": move,
    "dedupe": dedupe,
    "italic": italic,
    "unbold": unbold,
    "code": code,
}
