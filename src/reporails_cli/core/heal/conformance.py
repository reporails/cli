"""Conformance of a rewritten file against its plan: edits applied as written, nothing else moved, each op met."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from difflib import SequenceMatcher

from reporails_cli.core.heal.plan import apply_edits
from reporails_cli.core.lint.client_checks import running_sentences, sentence_instructions
from reporails_cli.core.mapper.md_parser import code_spans, emphasis_runs
from reporails_cli.core.mapper.structure import read_structure
from reporails_cli.core.platform.dto.heal_plan import Deviation, Edit, Plan, Slot
from reporails_cli.core.platform.dto.ruleset import Atom


def _slot_lines(slot: Slot, headings: Sequence[int], total: int) -> range:
    """The 1-based lines a slot may rewrite: its line, or its line to the next heading for a section."""
    if slot.bound == "line":
        return range(slot.line, slot.line + 1)
    end = next((h for h in headings if h > slot.line), total + 1)
    return range(slot.line, end)


def _emphasis(line: str) -> tuple[int, int]:
    runs = emphasis_runs(line)
    return sum(1 for r in runs if not r.strong), sum(1 for r in runs if r.strong)


_Found = tuple[str, str] | None


def _split_met(edit: Edit, new_line: int, text: str, atoms: Sequence[Atom]) -> _Found:  # noqa: ARG001
    packed = [
        len(sentence_instructions(s)) for s in running_sentences(list(atoms)) if any(a.line == new_line for a in s)
    ]
    worst = max(packed, default=1)
    return ("instr:1", f"instr:{worst}") if worst > 1 else None


def _direct_met(edit: Edit, new_line: int, text: str, atoms: Sequence[Atom]) -> _Found:  # noqa: ARG001
    hedged = any(a.modality == "hedged" for a in atoms if a.line == new_line)
    return ("mod:direct", "mod:hedged") if hedged else None


def _negation_met(edit: Edit, new_line: int, text: str, atoms: Sequence[Atom]) -> _Found:  # noqa: ARG001
    held = any(a.charge_value == -1 for a in atoms if a.line == new_line)
    return None if held else ("charge:-1", "charge:other")


def _italic_met(edit: Edit, new_line: int, text: str, atoms: Sequence[Atom]) -> _Found:  # noqa: ARG001
    return None if _emphasis(text)[0] > _emphasis(edit.before)[0] else ("italic:+1", "italic:same")


def _unbold_met(edit: Edit, new_line: int, text: str, atoms: Sequence[Atom]) -> _Found:  # noqa: ARG001
    return None if _emphasis(text)[1] < _emphasis(edit.before)[1] else ("bold:-1", "bold:same")


def _code_met(edit: Edit, new_line: int, text: str, atoms: Sequence[Atom]) -> _Found:  # noqa: ARG001
    more = len(code_spans(text)) > len(code_spans(edit.before))
    return None if more else ("code:+1", "code:same")


_OP_CHECKS = {
    "split": _split_met,
    "direct": _direct_met,
    "negation-form": _negation_met,
    "italic": _italic_met,
    "unbold": _unbold_met,
    "code": _code_met,
}


def _planned_lines(
    edits: Sequence[Edit], slots: Sequence[Slot], old_raw: Sequence[str], where: Mapping[int, int]
) -> set[int]:
    """The plan applied lines the rewrite may change: those a slot covers and those an edit wrote."""
    headings = read_structure("".join(line.rstrip("\r\n") + "\n" for line in old_raw)).headings
    slotted = {where[n - 1] for s in slots for n in _slot_lines(s, headings, len(old_raw)) if n - 1 in where}
    edited = {
        where[e.line - 1 + k] for e in edits if e.after is not None for k in range(e.span) if e.line - 1 + k in where
    }
    return slotted | edited


def _unplanned_changes(
    file: str, edits: Sequence[Edit], slots: Sequence[Slot], old_raw: Sequence[str], new: Sequence[str]
) -> tuple[list[Deviation], dict[int, int], dict[int, int]]:
    """The changes outside the plan, where each old line went in the plan applied to the old lines, and
    which of the applied lines the rewrite left as they are (applied index to new index)."""
    expected, where = apply_edits(old_raw, edits)
    free = _planned_lines(edits, slots, old_raw, where)
    back = {applied: old for old, applied in where.items()}
    ops = SequenceMatcher(None, expected, list(new), autojunk=False).get_opcodes()
    mapped = {i1 + k: j1 + k for tag, i1, i2, j1, _ in ops if tag == "equal" for k in range(i2 - i1)}
    out = [
        Deviation(file, back.get(min(i1, len(expected) - 1), i1) + 1, "outside", "", "same", "changed")
        for tag, i1, i2, _, _ in ops
        if tag != "equal" and not _is_planned(i1, i2, free)
    ]
    return out, where, mapped


def _is_planned(first: int, end: int, free: set[int]) -> bool:
    """Whether a changed range of applied lines lies in lines the rewrite may change; an insertion
    must sit beside one."""
    return all(i in free for i in range(first, end)) if end > first else (first - 1 in free or first in free)


def check_plan(
    plan: Plan,
    old_lines_by_file: Mapping[str, Sequence[str]],
    new_lines_by_file: Mapping[str, Sequence[str]],
    new_atoms_by_file: Mapping[str, Sequence[Atom]],
) -> list[Deviation]:
    """Where the rewritten files depart from the plan.

    Every line outside the plan's edit and slot lines is unchanged (line shifts a move or a dedupe makes are
    allowed), each edit's line reads as its `after`, and each op holds on the new atoms.
    """
    out: list[Deviation] = []
    for file, old_raw in old_lines_by_file.items():
        new = [line.rstrip("\r\n") for line in new_lines_by_file.get(file, ())]
        out.extend(_check_file(plan, file, old_raw, new, new_atoms_by_file.get(file, ())))
    return out


def _check_file(
    plan: Plan, file: str, old_raw: Sequence[str], new: Sequence[str], atoms: Sequence[Atom]
) -> list[Deviation]:
    """One file's departures from the plan: changes outside the planned lines, then each edit's check."""
    edits = [e for e in plan.edits if e.file == file]
    slots = [s for s in plan.slots if s.file == file]
    out, where, mapped = _unplanned_changes(file, edits, slots, old_raw, new)
    expected, _ = apply_edits(old_raw, edits)
    for e in edits:
        out.extend(_check_edit(e, file, where, mapped, new, atoms, expected))
    return out


def _check_edit(
    edit: Edit,
    file: str,
    where: Mapping[int, int],
    mapped: Mapping[int, int],
    new: Sequence[str],
    atoms: Sequence[Atom],
    expected: Sequence[str],
) -> list[Deviation]:
    def dev(want: str, got: str) -> list[Deviation]:
        return [Deviation(file, edit.line, edit.op, edit.rule, want, got)]

    here = where.get(edit.line - 1)
    if edit.op == "dedupe":
        gone = [line for line in edit.before.split("\n") if line.strip()]
        return (
            dev("gone", "present") if any(list(new).count(line) > list(expected).count(line) for line in gone) else []
        )
    if here is None or here not in mapped:
        return dev("after", "changed")
    if edit.move_after is not None:
        anchor = where.get(edit.move_after - 1)
        if anchor is None or anchor not in mapped:
            return dev("after:anchor", "changed")
        return [] if mapped[here] > mapped[anchor] else dev("order:after", "order:before")
    check = _OP_CHECKS.get(edit.op)
    first = mapped[here]
    text = "\n".join(new[first : first + (edit.after or "").count("\n") + 1])
    found = check(edit, first + 1, text, atoms) if check else None
    return dev(*found) if found else []
