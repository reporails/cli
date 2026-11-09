"""Shapes of a heal run: the fixes it writes, the preservation baseline and the checks' pairs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.mapping import LineSpans
from reporails_cli.core.platform.dto.ruleset import Atom, AtomFormat, Modality
from reporails_cli.core.platform.dto.structure import DocumentStructure


class HealOutcome(NamedTuple):
    """One file's heal: what was written (`None` when nothing could be), why nothing was, and the project root."""

    written: KeyedResult | None
    withheld: str
    scan_root: Path


class NamedTargets(NamedTuple):
    """The resolved files and folders a run's targets name; heal writes what they name and nothing beside."""

    files: frozenset[Path]
    dirs: frozenset[Path]


@dataclass(frozen=True)
class Suggestion:
    """A missing section a file's finding points at — not written."""

    rule_id: str
    file_path: str
    section: str
    description: str


@dataclass
class KeyedResult:
    """What a keyed heal pass did: fixes written, places left to a decision, files put back."""

    fixes: list[JsonObject] = field(default_factory=list)
    decisions: list[JsonObject] = field(default_factory=list)
    put_back: list[JsonObject] = field(default_factory=list)


@dataclass(frozen=True)
class MechanicalFix:
    """Outcome of a mechanical fix applied to raw file content."""

    line: int
    before: str
    after: str


@dataclass(frozen=True)
class Prose:
    """A file's lines with the places the markdown parse reads as plain paragraphs and as code."""

    lines: list[str]
    paragraphs: list[tuple[int, int]]
    spans: list[LineSpans]

    def bounds(self, idx: int) -> tuple[int, int] | None:
        """First and last line of the plain paragraph holding line `idx`, or None when it is not one."""
        return next(((lo, hi) for lo, hi in self.paragraphs if lo <= idx <= hi), None)


class Located(NamedTuple):
    """A paragraph flattened to one string, the (line, column) of each character and the
    [start, end) of the atom's sentence in it."""

    flat: str
    where: list[tuple[int, int]]
    start: int
    end: int


@dataclass(frozen=True)
class SnapshotAtom:
    """One snapshotted atom — the fields the compare needs, nothing more."""

    line: int
    text: str
    charge_value: int
    named_tokens: tuple[str, ...]
    format: AtomFormat
    embedding_int8: tuple[int, ...] | None
    heading_context: str = ""
    scope_conditional: bool = False
    heading: bool = False
    plain_text: str = ""
    modality: Modality = "none"


@dataclass(frozen=True)
class Snapshot:
    """A file's preservation baseline, taken before a rewrite."""

    file_path: str
    text: str
    atoms: tuple[SnapshotAtom, ...]
    score: float | None
    structure: DocumentStructure
    imports: tuple[str, ...]
    relation_lines: frozenset[int] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Pair:
    """A matched instruction: the original atom and its rewrite, each with the sentence it sits in."""

    old: SnapshotAtom
    new: Atom
    old_sentence: str
    new_sentence: str

    def entry(self) -> JsonObject:
        """The pair as a report entry: each side's line and sentence."""
        return {
            "line": self.old.line,
            "text": self.old_sentence,
            "new_line": self.new.line,
            "new_text": self.new_sentence,
        }


@dataclass(frozen=True)
class Condition:
    """The content words a condition governs; `restriction` when a restricting word that
    limits where or to what the instruction applies (`only`) opens it rather than a frame marker
    or an exclusion."""

    words: frozenset[str]
    restriction: bool
