"""Embedded charge-marker scans over classified atoms.

A neutral atom whose text carries charge language becomes ambiguous; a charged atom whose
text carries an opposite-direction marker records it.
"""

from __future__ import annotations

import re

from reporails_cli.core.mapper.charge_floors import TABLE_HEADER_RULE
from reporails_cli.core.mapper.fence_atoms import is_fence_block
from reporails_cli.core.mapper.md_parser import code_spans, link_spans, replace_spans
from reporails_cli.core.mapper.prose_split import sentence_spans
from reporails_cli.core.platform.dto.ruleset import Atom

# Patterns that indicate charge language in text classified as neutral.
# These are the "prohibited words" — if they appear in neutral atoms,
# the atom is flagged for review.
_EMBEDDED_CONSTRAINT_RE = re.compile(
    r"\b("
    r"never|don'?t|do\s+not|must\s+not|should\s+not|cannot|can'?t"
    r"|avoid\b|refrain|prohibit"
    r")\b",
    re.IGNORECASE,
)
_EMBEDDED_DIRECTIVE_RE = re.compile(
    r"\b("
    r"must|shall|always|ensure that|require that"
    r")\b",
    re.IGNORECASE,
)
_EMBEDDED_IMPERATIVE_RE = re.compile(
    r"("
    # Only non-ambiguous verbs — words that are almost always imperative
    # at sentence start. Excludes verb-noun words (test, build, set, check,
    # run, read, trace, etc.) that produce false positives on descriptions.
    r"use|add|create|install|configure|make"
    r"|update|follow|keep|write|verify|ensure"
    r"|remove|delete|include|exclude|specify|define|implement"
    r")\b",
    re.IGNORECASE,
)


def _strip_refs_for_marker_scan(text: str) -> str:
    """Drop link labels and targets and code spans before marker detection.

    A charge word inside a link label or a code span is referential, not
    instructional, so it must not promote a neutral atom to AMBIGUOUS.
    """
    spans: list[tuple[int, int, *tuple[object, ...]]] = [*code_spans(text), *link_spans(text)]
    return replace_spans(text, spans, lambda _span: " ")


def _constraint_markers(text: str) -> list[str]:
    """The `constraint:<word>` markers `text` carries."""
    return [f"constraint:{m.group().strip()}" for m in _EMBEDDED_CONSTRAINT_RE.finditer(text)]


def _directive_markers(text: str) -> list[str]:
    """The `directive:<word>` and `imperative:<word>` markers `text` carries."""
    sentence_starts = (_EMBEDDED_IMPERATIVE_RE.match(text, start, end) for start, end in sentence_spans(text))
    return [f"directive:{m.group().strip()}" for m in _EMBEDDED_DIRECTIVE_RE.finditer(text)] + [
        f"imperative:{m.group(1).strip()}" for m in sentence_starts if m
    ]


# Rules that produce correct neutralizations — don't second-guess these.
# Backtick filter: ROOT verb inside code markup (not an instruction).
# Third person: "The system processes..." (description, not instruction).
# Structural: tables, file listings, pipe references.
# Table header: a column label (`Don't | Do`) whose charge words name columns.
_TRUSTED_NEUTRAL_RULES = frozenset(
    {
        "third_person",
        "short_text",
        "no_words",
        TABLE_HEADER_RULE,
    }
)


def _scan_neutral_for_embedded_markers(atoms: list[Atom]) -> None:
    """Scan neutral atoms for embedded charge markers.

    Reclassifies to AMBIGUOUS when charge language appears in text that
    the classifier couldn't resolve. AMBIGUOUS atoms are excluded from
    diagnostics until the user rephrases them. The map records what
    markers were found so diagnostics can suggest specific fixes.

    Unambiguous instruction language is required: what cannot be classified
    is not scored.
    """
    for atom in atoms:
        if atom.charge != "NEUTRAL" or atom.kind == "heading":
            continue
        # A neutral whole-fence BLOCK is literal code/diagram text, never scanned for
        # embedded charge language — mirrors the same guard in `_split_mixed_charge_atoms`
        # and `_split_charge_boundaries`.
        if is_fence_block(atom):
            continue
        if atom.rule in _TRUSTED_NEUTRAL_RULES:
            continue
        text = _strip_refs_for_marker_scan(atom.text)
        markers = _constraint_markers(text) + _directive_markers(text)
        if markers:
            atom.embedded_charge_markers = markers
            atom.charge = "AMBIGUOUS"


def _scan_charged_for_compound_markers(atoms: list[Atom]) -> None:
    """Detect opposite-direction markers in charged atoms.

    A directive like "mention it — don't delete it" contains both a
    directive verb and a constraint negation. The classifier picks one
    charge; this scanner records the opposite-direction signal on the atom
    so a later consumer can recognize it as a compound instruction rather
    than treat it as a plain one-sided directive or constraint.

    Does NOT change the atom's charge.
    """
    for atom in atoms:
        if atom.charge_value == 0 or atom.kind == "heading":
            continue
        text = _strip_refs_for_marker_scan(atom.text)
        opposite = _constraint_markers(text) if atom.charge_value == 1 else _directive_markers(text)
        if opposite:
            atom.embedded_charge_markers = opposite
