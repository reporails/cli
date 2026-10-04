"""A file's preservation baseline: the text and the instruction atoms the mapper read from it
before a rewrite, and the atoms of a rewritten file the checks compare against.

Nothing here reads a file: the caller hands over the text and the map.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from reporails_cli.core.heal.preservation.words import NEGATION_RE, content_words
from reporails_cli.core.lint.content_queries import instruction_atoms_for_file
from reporails_cli.core.mapper.structure import read_structure
from reporails_cli.core.platform.dto.ruleset import Atom
from reporails_cli.core.platform.dto.structure import DocumentStructure
from reporails_cli.core.platform.policy.negative_headings import is_negative_heading


@dataclass(frozen=True)
class SnapshotAtom:
    """One snapshotted atom — the fields the compare needs, nothing more."""

    line: int
    text: str
    charge_value: int
    named_tokens: tuple[str, ...]
    format: str
    embedding_int8: tuple[int, ...] | None
    heading_context: str = ""
    scope_conditional: bool = False
    heading: bool = False
    plain_text: str = ""
    modality: str = "none"


@dataclass(frozen=True)
class Snapshot:
    """A file's preservation baseline, taken before a rewrite."""

    file_path: str
    text: str
    atoms: tuple[SnapshotAtom, ...]
    score: float | None
    relation_lines: frozenset[int] = field(default_factory=frozenset)
    structure: DocumentStructure = field(init=False)

    def __post_init__(self) -> None:
        # The block structure of `text`, read once with the baseline.
        object.__setattr__(self, "structure", read_structure(self.text))


def is_instruction_heading(atom: Any) -> bool:
    """Whether a heading atom is an instruction of its own: charged, and not a bare negative label.
    A neutral heading and a bare negative heading are left to the structure checks."""
    return atom.charge_value != 0 and not is_negative_heading(atom.text)


def is_hedge_fragment(atom: Any) -> bool:
    """Whether `atom` is nothing but a hedge (`Consider`, `You should`) — the lead-in the mapper
    reads as an instruction of its own when it cuts a hedged sentence in two."""
    return atom.modality == "hedged" and not content_words(atom.plain_text) and not NEGATION_RE.search(atom.plain_text)


def take_snapshot(
    file_path: str, text: str, ruleset_map: Any, score: float | None, relation_lines: Any = ()
) -> Snapshot:
    """The baseline of `file_path`, whose content is `text` and whose atoms `ruleset_map` holds
    (`None` for a file with none): list objects and neutral or bare negative headings left out."""
    atoms = tuple(
        SnapshotAtom(
            line=a.line,
            text=a.text,
            charge_value=a.charge_value,
            named_tokens=tuple(a.named_tokens),
            format=a.format,
            embedding_int8=a.embedding_int8,
            heading_context=a.heading_context,
            scope_conditional=a.scope_conditional,
            heading=a.kind == "heading",
            plain_text=a.plain_text,
            modality=a.modality,
        )
        for a in (instruction_atoms_for_file(ruleset_map, file_path) if ruleset_map is not None else ())
        if a.kind != "heading" or a.charge_value != 0 or is_negative_heading(a.text)
    )
    return Snapshot(file_path=file_path, text=text, atoms=atoms, score=score, relation_lines=frozenset(relation_lines))


def rewritten_atoms(new_map: Any, file_path: str) -> list[Atom]:
    """`new_map`'s instruction atoms of `file_path` (list objects and hedge lead-ins left out, an
    instruction heading included), in file order."""
    atoms = (
        a
        for a in (instruction_atoms_for_file(new_map, file_path) if new_map is not None else ())
        if (a.kind != "heading" or is_instruction_heading(a)) and not is_hedge_fragment(a)
    )
    return sorted(atoms, key=lambda a: (a.line, a.position_index))
