"""Build a heal plan: the scripted edits and the slots a rewrite fills, from a list of ops."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from reporails_cli.core.heal.transforms import TRANSFORMS, atoms_at, dedupe
from reporails_cli.core.platform.dto.heal_plan import SCRIPTABLE_OPS, Edit, Plan, PlanOp, Refusal, Slot
from reporails_cli.core.platform.dto.ruleset import Atom

PartnerKey = tuple[str, int]


def _slot(op: PlanOp, found: Sequence[Atom]) -> Slot:
    return Slot(
        file=op.file,
        line=op.line,
        pi=op.pi,
        op=op.op,
        rule=op.rule,
        text=" ".join(a.text for a in found),
        bound="section" if op.op == "elaborate" else "line",
    )


def _partner(op: PlanOp, partner_atoms: Mapping[PartnerKey, Atom] | None) -> Atom | None:
    """The partner atom `expect["keep"]` names, when the caller passed it."""
    keep = op.expect.get("keep") or []
    if not partner_atoms or len(keep) != 2:
        return None
    return partner_atoms.get((str(keep[0]), int(str(keep[1]))))


def _touched(edit: Edit) -> set[int]:
    lines = set(range(edit.line, edit.line + edit.span))
    if edit.move_after is not None:
        lines.add(edit.move_after)
    return lines


def build_plan(
    ops: Sequence[PlanOp],
    atoms_by_file: Mapping[str, Sequence[Atom]],
    lines_by_file: Mapping[str, Sequence[str]],
    partner_atoms: Mapping[PartnerKey, Atom] | None = None,
) -> Plan:
    """Turn ops into edits (scriptable ops that apply safely), slots (everything else) and refusals.

    An op whose atom is missing from the map is refused as `stale map`. Ops run bottom to top within a
    file; an op whose line an earlier edit already touches becomes a slot. `partner_atoms` maps a
    dedupe or keep-cut op's `expect["keep"]` `(file, line)` to the partner atom.
    """
    edits: list[Edit] = []
    slots: list[Slot] = []
    refused: list[Refusal] = []
    touched: dict[str, set[int]] = {}
    for op in sorted((o for o in ops if o.op != "together"), key=lambda o: (o.file, -o.line, o.pi or 0)):
        atoms = atoms_by_file.get(op.file, ())
        lines = lines_by_file.get(op.file, ())
        found = atoms_at(atoms, op.line, op.pi)
        if not found or not 0 < op.line <= len(lines):
            refused.append(Refusal(op, "stale map"))
            continue
        edit = None
        if op.op in SCRIPTABLE_OPS and op.line not in touched.get(op.file, set()):
            if op.op == "dedupe":
                edit = dedupe(op, atoms, lines, _partner(op, partner_atoms))
            else:
                edit = TRANSFORMS[op.op](op, atoms, lines)
        if edit is not None and _touched(edit) & touched.get(op.file, set()):
            edit = None
        if edit is None:
            slots.append(_slot(op, found))
            continue
        touched.setdefault(op.file, set()).update(_touched(edit))
        edits.append(edit)
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
