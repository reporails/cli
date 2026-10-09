"""Build a heal plan: the scripted edits and the slots a rewrite fills, from a list of ops."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace

from reporails_cli.core.heal.op_guide import LINE_LEAVING_OPS
from reporails_cli.core.heal.transforms import TRANSFORMS, atoms_at, dedupe, split_or_reason
from reporails_cli.core.lint.content_queries import own_atoms
from reporails_cli.core.platform.dto.heal_plan import (
    IN_PLACE_OPS,
    SCRIPTABLE_OPS,
    Edit,
    Folded,
    Plan,
    PlanOp,
    Refusal,
    Slot,
)
from reporails_cli.core.platform.dto.ruleset import Atom

PartnerKey = tuple[str, int]


def _slot(op: PlanOp, found: Sequence[Atom], change: str = "") -> Slot:
    return Slot(
        file=op.file,
        line=op.line,
        pi=op.pi,
        op=op.op,
        rule=op.rule,
        text=" ".join(a.text for a in found),
        bound="section" if op.op == "elaborate" else "line",
        change=change,
    )


def _scripted(
    op: PlanOp, atoms: Sequence[Atom], lines: Sequence[str], partner_atoms: Mapping[PartnerKey, Atom] | None
) -> tuple[Edit | None, str]:
    """The edit a script makes for the op, or None with the one change a refused split allows ("" for any other)."""
    if op.op == "dedupe":
        return dedupe(op, atoms, lines, _partner(op, partner_atoms)), ""
    if op.op == "split":
        outcome = split_or_reason(op, atoms, lines)
        return (outcome, "") if isinstance(outcome, Edit) else (None, outcome)
    return TRANSFORMS[op.op](op, atoms, lines), ""


def _partner(op: PlanOp, partner_atoms: Mapping[PartnerKey, Atom] | None) -> Atom | None:
    """The partner atom `expect["keep"]` names, when the caller passed it."""
    keep = op.expect.get("keep") or []
    if not partner_atoms or len(keep) != 2:
        return None
    return partner_atoms.get((str(keep[0]), int(str(keep[1]))))


def _nth(atoms: Sequence[Atom], op: PlanOp) -> int | None:
    """The place of the atom the op addresses among the atoms of its line (first is 0); None when the op names
    no atom. The position index counts atoms across the file and moves when an earlier line loses one; the
    place on the line does not."""
    if op.pi is None:
        return None
    on_line = sorted((a for a in atoms if a.line == op.line), key=lambda a: a.position_index)
    return next((i for i, a in enumerate(on_line) if a.position_index == op.pi), None)


def _fold(
    op: PlanOp,
    atoms: Sequence[Atom],
    lines: Sequence[str],
    prior: Edit,
    partner_atoms: Mapping[PartnerKey, Atom] | None,
) -> Edit | None:
    """`prior` with the in-place `op` run on its edited line and folded in; None when `prior` is not a one-line
    in-place edit of the op's line, or the transform refuses the edited text."""
    if prior.op not in IN_PLACE_OPS or prior.after is None or prior.span != 1 or "\n" in prior.after:
        return None
    edited = list(lines)
    edited[op.line - 1] = prior.after
    nxt, _ = _scripted(op, atoms, edited, partner_atoms)
    if nxt is None or nxt.after is None or nxt.before != prior.after or "\n" in nxt.after:
        return None
    return replace(prior, after=nxt.after, folded=(*prior.folded, Folded(op.op, op.rule, _nth(atoms, op))))


def _touched(edit: Edit) -> set[int]:
    lines = set(range(edit.line, edit.line + edit.span))
    if edit.move_after is not None:
        lines.add(edit.move_after)
    return lines


def _fold_into(
    edits: list[Edit],
    op: PlanOp,
    atoms: Sequence[Atom],
    lines: Sequence[str],
    partner_atoms: Mapping[PartnerKey, Atom] | None,
) -> bool:
    """Fold `op` into the edit already made at its line, in place in `edits`; whether it folded."""
    for i, prior in enumerate(edits):
        if prior.file == op.file and prior.line == op.line:
            merged = _fold(op, atoms, lines, prior, partner_atoms)
            if merged is not None:
                edits[i] = merged
            return merged is not None
    return False


_TEXT_OPS = frozenset({"direct", "negation-form"})


def _order(op: PlanOp) -> tuple[str, int, int, int]:
    """Ops run bottom to top; on one line the ops that change the words come before the formatting ones, which
    then run on the changed text."""
    return (op.file, -op.line, 0 if op.op in _TEXT_OPS else 1, op.pi or 0)


def leaving_lines(plan: Plan) -> set[int]:
    """The lines of a plan a rewrite may let go: those an edit of a line-leaving op (`LINE_LEAVING_OPS`)
    removes and those a slot of such an op leaves for the rewrite to remove."""
    return {n for e in plan.edits if e.op in LINE_LEAVING_OPS for n in range(e.line, e.line + e.span)} | {
        s.line for s in plan.slots if s.op in LINE_LEAVING_OPS
    }


def build_plan(
    ops: Sequence[PlanOp],
    atoms_by_file: Mapping[str, Sequence[Atom]],
    lines_by_file: Mapping[str, Sequence[str]],
    partner_atoms: Mapping[PartnerKey, Atom] | None = None,
) -> Plan:
    """Turn ops into edits (scriptable ops that apply safely), slots (everything else) and refusals.

    An op whose atom is missing from the map is refused as `stale map`; one on a line that holds an atom
    written in an imported file, as `imports_expand` (the file's own atoms keep their own lines).
    Ops run bottom to top within a file. An in-place op (`code`, `unbold`, `italic`, `direct`,
    `negation-form`) whose line an earlier in-place edit rewrote runs on the edited text and folds into that
    edit; any other op whose line an earlier edit already touches, and a folded op the transform refuses,
    becomes a slot. `partner_atoms` maps a dedupe or keep-cut op's `expect["keep"]` `(file, line)` to the
    partner atom.
    """
    edits: list[Edit] = []
    slots: list[Slot] = []
    refused: list[Refusal] = []
    touched: dict[str, set[int]] = {}
    for op in sorted((o for o in ops if o.op != "together"), key=_order):
        atoms = atoms_by_file.get(op.file, ())
        lines = lines_by_file.get(op.file, ())
        found = atoms_at(atoms, op.line, op.pi)
        if not found or not 0 < op.line <= len(lines):
            refused.append(Refusal(op, "stale map"))
            continue
        on_line = [a for a in atoms if a.line == op.line]
        if len(own_atoms(on_line)) < len(on_line):
            refused.append(Refusal(op, "imports_expand"))
            continue
        edit, change = None, ""
        if op.line in touched.get(op.file, set()):
            if op.op in IN_PLACE_OPS and _fold_into(edits, op, atoms, lines, partner_atoms):
                continue
        elif op.op in SCRIPTABLE_OPS:
            edit, change = _scripted(op, atoms, lines, partner_atoms)
        if edit is not None and _touched(edit) & touched.get(op.file, set()):
            edit, change = None, ""
        if edit is None:
            slots.append(_slot(op, found, change))
            continue
        touched.setdefault(op.file, set()).update(_touched(edit))
        edits.append(replace(edit, nth=_nth(atoms, op)))
    edits.sort(key=lambda e: (e.file, e.line))
    slots.sort(key=lambda s: (s.file, s.line, s.pi or 0))
    return Plan(tuple(edits), tuple(slots), tuple(refused))


def apply_edits(lines: Sequence[str], edits: Sequence[Edit]) -> tuple[list[str], dict[int, int]]:
    """The lines (line endings dropped) after `edits`, and where each surviving original line (0-based)
    went. A removed line has no entry; a moved line maps to its new place."""
    body = [line.rstrip("\r\n") for line in lines]
    starts = {e.line - 1: e for e in edits}
    placed: dict[int, list[int]] = {}
    for e in edits:
        if e.move_after is not None:
            placed.setdefault(e.move_after - 1, []).append(e.line - 1)
    out: list[str] = []
    where: dict[int, int] = {}
    i = 0
    while i < len(body):
        edit = starts.get(i)
        if edit is None:
            where[i] = len(out)
            out.append(body[i])
            span = 1
        else:
            span = edit.span
            if edit.after is not None:
                for k, text in enumerate(edit.after.split("\n")):
                    where.setdefault(i + k, len(out))
                    out.append(text)
        for n in range(i, i + span):
            for target in placed.get(n, []):
                where[target] = len(out)
                out.append(body[target])
        i += span
    return out, where
