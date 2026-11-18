"""A file's preservation baseline: the text and the instruction atoms the mapper read from it
before a rewrite, and the atoms of a rewritten file the checks compare against.

Nothing here reads a file: the caller hands over the text and the map.
"""

from __future__ import annotations

from collections.abc import Iterable

from reporails_cli.core.heal.preservation.words import AtomView
from reporails_cli.core.lint.content_queries import instruction_atoms_for_file, list_object_atoms_for_file
from reporails_cli.core.mapper.classify import hedge_cue_words
from reporails_cli.core.mapper.imports import import_refs
from reporails_cli.core.mapper.structure import read_structure
from reporails_cli.core.platform.dto.heal import Snapshot, SnapshotAtom
from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap


def is_instruction_heading(atom: AtomView) -> bool:
    """Whether a heading atom is an instruction of its own: charged, and not a bare negative label.
    A neutral heading and a bare negative heading are left to the structure checks."""
    return atom.charge_value != 0 and not atom.negative_heading


def is_hedge_fragment(atom: AtomView) -> bool:
    """Whether `atom` is nothing but a hedge (`Consider`, `You should`) — the lead-in the mapper
    reads as an instruction of its own when it cuts a hedged sentence in two: a hedged atom with no
    object whose predicate, when it has one, lies inside the hedge cue or is the whole atom; one with no
    slots read is a fragment only when its words end with the hedge cue (a hedged atom of one word is one)."""
    slots = atom.slots
    if atom.modality != "hedged":
        return False
    if slots is None or not slots.decoded:
        return len(atom.plain_text.split()) <= max(1, hedge_cue_words(atom.plain_text))
    predicate = slots.predicate_span
    whole = predicate is not None and atom.charge_value >= 0 and predicate[1] >= len(atom.plain_text.split())
    return slots.object_span is None and (
        predicate is None or whole or predicate[1] <= hedge_cue_words(atom.plain_text)
    )


def _snapshot_atom(a: Atom) -> SnapshotAtom:
    """The fields of `a` the compare reads."""
    return SnapshotAtom(
        line=a.line,
        text=a.text,
        charge_value=a.charge_value,
        named_tokens=tuple(a.named_tokens),
        format=a.format,
        embedding_int8=a.embedding_int8,
        heading_context=a.heading_context,
        scope_conditional=a.scope_conditional,
        negative_heading=a.negative_heading,
        plain_text=a.plain_text,
        modality=a.modality,
        slots=a.slots,
    )


def take_snapshot(
    file_path: str, text: str, ruleset_map: RulesetMap | None, score: float | None, relation_lines: Iterable[int] = ()
) -> Snapshot:
    """The baseline of `file_path`, whose content is `text` and whose atoms `ruleset_map` holds
    (`None` for a file with none): list objects kept apart in `list_objects`, every heading kept."""
    if ruleset_map is None:
        return make_snapshot(file_path, text, (), score, relation_lines)
    return make_snapshot(
        file_path,
        text,
        tuple(_snapshot_atom(a) for a in instruction_atoms_for_file(ruleset_map, file_path, own=True)),
        score,
        relation_lines,
        list_objects=tuple(_snapshot_atom(a) for a in list_object_atoms_for_file(ruleset_map, file_path)),
    )


def make_snapshot(
    file_path: str,
    text: str,
    atoms: tuple[SnapshotAtom, ...],
    score: float | None,
    relation_lines: Iterable[int] = (),
    *,
    list_objects: tuple[SnapshotAtom, ...] = (),
) -> Snapshot:
    """A baseline of `file_path` holding `atoms` (and the list items read as an instruction's object,
    `list_objects`), with the block structure and `@` imports of `text` read once."""
    return Snapshot(
        file_path=file_path,
        text=text,
        atoms=atoms,
        score=score,
        structure=read_structure(text),
        imports=tuple(import_refs(text)),
        relation_lines=frozenset(relation_lines),
        list_objects=list_objects,
    )


def rewritten_atoms(new_map: RulesetMap | None, file_path: str) -> list[Atom]:
    """`new_map`'s instruction atoms of `file_path` (list objects and hedge lead-ins left out, an
    instruction heading included), in file order."""
    atoms = (
        a
        for a in (instruction_atoms_for_file(new_map, file_path, own=True) if new_map is not None else ())
        if (a.kind != "heading" or is_instruction_heading(a)) and not is_hedge_fragment(a)
    )
    return sorted(atoms, key=lambda a: (a.line, a.position_index))
