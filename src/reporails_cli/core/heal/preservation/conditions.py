"""Wording of the matched instructions in the preservation check: a hedge made direct (listed), a
hedge made an absolute the line never had, a restriction added without a condition word, a
condition added, and a condition dropped.

Hedged and absolute instructions are read from the mapper's `modality`, conditions from its
`scope_conditional`; the words that mark a condition, a restriction or an absolute come from the
mapper's classifier.
"""

from __future__ import annotations

import os
import re
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import Any

from reporails_cli.core.heal.preservation.snapshot import SnapshotAtom
from reporails_cli.core.heal.preservation.words import STOPWORDS, WORD_RE, content_words, prose_text, prose_words
from reporails_cli.core.mapper.classify import (
    CONDITION_CONJUNCTIONS,
    CONDITION_OPENERS,
    CONDITION_QUANTIFIERS,
    CONDITIONAL_MARKERS,
    DETERMINERS,
    SCOPE_PREPOSITIONS,
    SCOPE_RESTRICTORS,
    absolute_cues,
    has_hedge_cue,
)
from reporails_cli.core.mapper.prose_split import split_prose_sentences

# Thresholds.
_SCOPE_REACH = 3  # words after a scope cue that make the scope it adds
_NEUTRAL_COVERAGE = 0.75  # share of a new instruction's words a hedged line the mapper read as prose must hold

_CLAUSE_RE = re.compile(r"[,;:()—]")

# Atoms of a file by line number, in file order.
ByLine = dict[int, list[Any]]


@dataclass(frozen=True)
class Pair:
    """A matched instruction: the original atom and its rewrite, each with the sentence it sits in."""

    old: SnapshotAtom
    new: Any
    old_sentence: str
    new_sentence: str

    def entry(self) -> dict[str, Any]:
        return {
            "line": self.old.line,
            "text": self.old_sentence,
            "new_line": self.new.line,
            "new_text": self.new_sentence,
        }


def by_line(atoms: Any) -> ByLine:
    """`atoms` bucketed by line number, in the order given."""
    out: ByLine = {}
    for atom in atoms:
        out.setdefault(atom.line, []).append(atom)
    return out


def sentence_of(atoms_by_line: ByLine, atom: Any) -> str:
    """The sentence of `atom`'s line that holds it (the line's atoms joined, cut by the mapper's
    sentence splitter); the whole line when none does."""
    line = " ".join(a.text for a in atoms_by_line.get(atom.line, ())) or atom.text
    needle = atom.text.strip().lower()[:15]
    for sentence in split_prose_sentences(line, atom.named_tokens):
        if needle and needle in sentence.lower():
            return sentence
    return line


def pair_up(
    snap_atoms: list[SnapshotAtom], matched_new_for: dict[int, Any], old_by_line: ByLine, new_by_line: ByLine
) -> list[Pair]:
    """Each matched instruction as a `Pair`."""
    out = []
    for sa in snap_atoms:
        match = matched_new_for.get(id(sa))
        if sa.charge_value != 0 and match is not None:
            out.append(Pair(sa, match, sentence_of(old_by_line, sa), sentence_of(new_by_line, match)))
    return out


def _hedged(atom: Any) -> bool:
    """Whether `atom` gives its instruction as a suggestion: the mapper reads a charged atom's
    modality; a line it read as plain prose shows a hedge word."""
    return atom.modality == "hedged" if atom.charge_value != 0 else has_hedge_cue(atom.plain_text)


def made_direct(
    pairs: list[Pair],
    snap_atoms: list[SnapshotAtom],
    new_atoms: list[Any],
    matched_new_for: dict[int, Any],
    sentences: tuple[ByLine, ByLine],
) -> list[dict[str, Any]]:
    """Each instruction whose original was a suggestion (`prefer`, `consider`, `should`, `try`, ...)
    and whose rewrite is not: the change is allowed and listed with the sentence before and after,
    so the report can show it. A rewritten instruction with no matched original counts when its
    words come from a hedged line the mapper read as plain prose (`You might want to run the
    linter`)."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for p in pairs:
        key = (p.old.line, p.new.line)
        if key not in seen and _hedged(p.old) and p.new.modality != "hedged" and p.old_sentence != p.new_sentence:
            seen.add(key)
            out.append(p.entry())
    return out + _made_direct_from_prose(snap_atoms, new_atoms, matched_new_for, {e["line"] for e in out}, sentences)


def _made_direct_from_prose(
    snap_atoms: list[SnapshotAtom],
    new_atoms: list[Any],
    matched_new_for: dict[int, Any],
    done: set[int],
    sentences: tuple[ByLine, ByLine],
) -> list[dict[str, Any]]:
    old_by_line, new_by_line = sentences
    claimed = {id(m) for m in matched_new_for.values()}
    hedged_prose = [sa for sa in snap_atoms if sa.charge_value == 0 and not sa.heading and _hedged(sa)]
    out: list[dict[str, Any]] = []
    for na in new_atoms:
        words = content_words(na.text)
        if na.charge_value == 0 or id(na) in claimed or not words:
            continue
        for sa in hedged_prose:
            if sa.line in done or len(words & content_words(sa.text)) / len(words) < _NEUTRAL_COVERAGE:
                continue
            done.add(sa.line)
            out.append(Pair(sa, na, sentence_of(old_by_line, sa), sentence_of(new_by_line, na)).entry())
            break
    return out


def hedge_made_absolute(pairs: list[Pair], old_by_line: ByLine) -> list[dict[str, Any]]:
    """Each matched suggestion whose rewrite is an absolute (`Never`, `Always`) where the
    author's line had no such word."""
    out: list[dict[str, Any]] = []
    for p in pairs:
        if not _hedged(p.old) or p.new.modality != "absolute":
            continue
        known = set().union(*(absolute_cues(a.plain_text) for a in old_by_line.get(p.old.line, ())))
        if absolute_cues(p.new.plain_text) - known:
            out.append(p.entry())
    return out


_PLAIN_WORD_RE = re.compile(r"\w+")


def _forms(word: str) -> set[str]:
    """`word` with its plain singular and plural spellings (`test` / `tests`, `match` / `matches`)."""
    forms = {word, word + "s", word + "es"}
    if word.endswith("es"):
        forms.add(word[:-2])
    if word.endswith("s"):
        forms.add(word[:-1])
    return forms


def _known_words(old_by_line: ByLine, line: int) -> set[str]:
    """The words the author's line has: those of every snapshot atom on it, plus a code token that
    is one plain word (`except`); a path, a dotted name or a multi-word token adds none."""
    known: set[str] = set()
    for atom in old_by_line.get(line, ()):
        text: str = atom.plain_text
        for token in atom.named_tokens:
            if not _PLAIN_WORD_RE.fullmatch(token.strip("`")):
                text = text.replace(token.strip("`"), " ")
        known.update(w.lower() for w in WORD_RE.findall(text))
    return known


def _fresh(tail: list[str], known: set[str]) -> bool:
    """Whether `tail` holds a content word the author's line does not have."""
    return any(len(w) > 1 and w not in STOPWORDS and not _forms(w) & known for w in tail)


def _narrows(words: list[str], known: set[str]) -> bool:
    """Whether the rewrite's `words` add a restriction the author's line did not state: a
    restricting word it never used, or a place / time / thing it never named after a preposition."""
    for i, word in enumerate(words):
        tail = words[i + 1 : i + 1 + _SCOPE_REACH]
        if word in SCOPE_RESTRICTORS and word not in known:
            return True
        if word in SCOPE_PREPOSITIONS and _fresh(tail, known):
            return True
        if word == "for" and tail[:1] and tail[0] in DETERMINERS and _fresh(tail, known):
            return True
    return False


def _clauses(atom: Any, *, named: bool = False) -> list[list[str]]:
    """`atom`'s words, one list per comma / colon / parenthesis separated clause, named constructs
    left out unless `named` (a condition's words read the same backticked or not)."""
    parts = _CLAUSE_RE.split(prose_text(atom, named=named))
    return [w for w in ([t.lower() for t in WORD_RE.findall(part)] for part in parts) if w]


def narrowed_instructions(pairs: list[Pair], old_by_line: ByLine) -> list[dict[str, Any]]:
    """Each matched instruction whose rewrite adds words that restrict where, when or to what it
    applies, without an if / when / before frame (which `added_conditions` already reports)."""
    out: list[dict[str, Any]] = []
    for p in pairs:
        known = _known_words(old_by_line, p.old.line)
        known |= {f for w in known for f in _forms(w)}
        if any(_narrows(clause, known) for clause in _clauses(p.new)):
            out.append(p.entry())
    return out


def _marker_words(atom: Any, marked_before: AbstractSet[str] = frozenset()) -> set[str]:
    """The words of `atom` that may mark a condition: its prose words (a code token such as
    `except` marks nothing) and the code tokens the original already had as prose words."""
    return set(prose_words(atom)) | (set(prose_words(atom, named=True)) & marked_before)


def _conditional(atom: Any, marked_before: AbstractSet[str] = frozenset()) -> bool:
    """Whether `atom` holds a condition: the mapper reads a conditional frame, or the instruction
    is restricted by a word like `only` / `except` in its prose."""
    return atom.scope_conditional or bool(_marker_words(atom, marked_before) & SCOPE_RESTRICTORS)


# Words that only mark a condition or a quantifier over it: swapping one marker for another
# ("every time" -> "whenever", "prior to" -> "before") adds no content of its own.
_CONDITION_WORDS = frozenset(CONDITIONAL_MARKERS) | CONDITION_QUANTIFIERS

# Restricting words that exclude (`except`, `excluding`, `outside`): what they open is a condition
# on its own, so an addition to it widens the instruction.
_EXCLUSIONS = frozenset({"except", "excluding", "outside"})

_ENDING_REACH = 4  # letters an ending may add to a word and still be that word
_CONDITION_COVERAGE = 0.5  # share of the words a condition governs that its rewrite must still hold


@dataclass(frozen=True)
class _Condition:
    """The content words a condition governs; `restriction` when a restricting word that
    limits where or to what the instruction applies (`only`) opens it rather than a frame marker
    or an exclusion."""

    words: frozenset[str]
    restriction: bool


def _conditions(atom: Any, marked_before: AbstractSet[str] = frozenset()) -> list[_Condition]:
    """The words each condition of `atom` governs, one per condition: a clause with a frame
    marker (`if`, `unless`, `before`, `only`, ...) holds the content words after the marker, and
    conditions joined by `and` / `or` (`When tests fail and the branch is main`) are one each.
    A marker is a word of the prose (or one the original already had as a prose word, for a rewrite
    that backticks it); the words a condition governs include code tokens."""
    out: list[_Condition] = []
    prose = _marker_words(atom, marked_before)
    for clause in _clauses(atom, named=True):
        for i, word in enumerate(clause):
            if word in prose and (word in CONDITION_OPENERS or word in SCOPE_RESTRICTORS):
                conjuncts: list[list[str]] = [[]]
                for tail_word in clause[i + 1 :]:
                    if tail_word in CONDITION_CONJUNCTIONS:
                        conjuncts.append([])
                    else:
                        conjuncts[-1].append(tail_word)
                restriction = word in SCOPE_RESTRICTORS and word not in _EXCLUSIONS
                words = (content_words(" ".join(c)) - _CONDITION_WORDS for c in conjuncts)
                out.extend(_Condition(frozenset(g), restriction) for g in words if g)
                break
    return out


def _is_word_of(word: str, words: AbstractSet[str]) -> bool:
    """Whether `word` is one of `words`, in a plain singular / plural form or with a short ending
    added or dropped (`edit` / `editing`)."""
    if _forms(word) & words:
        return True
    for other in words:
        short, long_ = sorted((word, other), key=len)
        shared = len(os.path.commonprefix([short, long_]))
        if shared >= max(3, len(short) - 1) and len(long_) - len(short) <= _ENDING_REACH:
            return True
    return False


def _holds(governed: _Condition, rewrite_conditions: list[_Condition], original_conditions: list[_Condition]) -> bool:
    """Whether a condition of the rewrite stands for `governed`: it has enough of the words the
    original condition governs and no content word the original condition lacked (`If the build
    passes` is not `If the build fails`). Conditions joined by `and` / `or` share what follows the
    last one (`the build or the tests fail`), so when the rewrite's conditions together use exactly
    the words the original's do, reordering them holds. A restriction that limits the
    instruction (`Only use on trusted machines`; not an exclusion like `except`) keeps holding when
    the rewrite keeps every word of it and names more (`Only use remote debugging on trusted
    machines`): the restriction is the scope, not what the verb acts on."""
    for candidate in rewrite_conditions:
        held = sum(1 for w in governed.words if _is_word_of(w, candidate.words))
        if held / len(governed.words) >= _CONDITION_COVERAGE and all(
            _is_word_of(w, governed.words) for w in candidate.words
        ):
            return True
        if governed.restriction and held == len(governed.words):
            return True
    original_words = set().union(*(c.words for c in original_conditions))
    rewrite_words = set().union(*(c.words for c in rewrite_conditions))
    return (
        len(rewrite_conditions) == len(original_conditions)
        and all(_is_word_of(w, rewrite_words) for w in original_words)
        and all(_is_word_of(w, original_words) for w in rewrite_words)
    )


def dropped_conditions(pairs: list[Pair]) -> list[dict[str, Any]]:
    """Each matched instruction whose original holds a condition (if / when / before / after /
    unless / only ...) that its rewrite no longer holds: the rewrite has no condition at all, or no
    condition of it stands for one of the original's (`If the build fails, run X before Y`
    rewritten `Run X before Y` keeps `before` and loses `if the build fails`; `If the build passes`
    changes it; `When tests fail, ...` drops the second of `When tests fail and the branch is main`).
    A condition restated with its marker swapped, another form of its words or a pronoun is held;
    one that brings a word the original condition lacked is not."""
    out = []
    for p in pairs:
        if not _conditional(p.old):
            continue
        before = set(prose_words(p.old))
        rewrite_conditions = _conditions(p.new, before)
        original_conditions = _conditions(p.old)
        if not _conditional(p.new, before) or not all(
            _holds(g, rewrite_conditions, original_conditions) for g in original_conditions
        ):
            out.append(p.entry())
    return out


def _new_content_words(rewrite: str, original_words: set[str]) -> set[str]:
    """Content words of `rewrite` that neither the original line nor a plain singular/plural form
    of them has, leaving out words that only mark a condition."""
    return {w for w in content_words(rewrite) - _CONDITION_WORDS if not _forms(w) & original_words}


def added_conditions(snap_atoms: list[SnapshotAtom], matched_new_for: dict[int, Any]) -> list[dict[str, Any]]:
    """Each matched instruction that was not conditional, whose rewrite is conditional and carries
    a content word the author's line never had (every snapshot atom on that line counts as the
    author's line; singular and plural forms are the same word, and words that only mark a
    condition are not content). A rewrite that restates the author's own condition in other
    words, or spreads it over several lines, is not listed."""
    out: list[dict[str, Any]] = []
    for sa in snap_atoms:
        match = matched_new_for.get(id(sa))
        if sa.charge_value == 0 or match is None or sa.scope_conditional or not match.scope_conditional:
            continue
        original_words: set[str] = set()
        for other in snap_atoms:
            if other.line == sa.line:
                original_words |= content_words(other.text)
        if _new_content_words(match.text, original_words):
            out.append({"line": sa.line, "text": sa.text, "new_line": match.line, "new_text": match.text})
    return out
