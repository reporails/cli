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
from reporails_cli.core.heal.preservation.words import (
    STOPWORDS,
    WORD_RE,
    blank_named,
    content_words,
    named_key,
    prose_text,
    prose_words,
    word_forms,
)
from reporails_cli.core.mapper.classify import (
    CONDITION_CONJUNCTIONS,
    CONDITION_OPENERS,
    CONDITION_QUANTIFIERS,
    CONDITIONAL_MARKERS,
    COVERAGE_RESTRICTORS,
    DETERMINERS,
    GENERAL_QUANTIFIERS,
    PHRASE_PREPOSITIONS,
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
# Stands in a clause for each named construct that was there, so the words after it do not fall
# into the reach of the word before it.
_NAMED = "namedconstruct"
_SEGMENT_RE = re.compile(
    f"{_CLAUSE_RE.pattern}|\\b(?:{'|'.join(sorted(CONDITION_CONJUNCTIONS | {'then'}))})\\b", re.IGNORECASE
)
# What ends the phrase a scope preposition opens.
_PHRASE_END = PHRASE_PREPOSITIONS | CONDITION_CONJUNCTIONS

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


def _known_words(old_by_line: ByLine, line: int) -> set[str]:
    """The words the author's line has: those of every snapshot atom on it, plus a code token that
    is one plain word (`except`); a path, a dotted name or a multi-word token adds none."""
    known: set[str] = set()
    for atom in old_by_line.get(line, ()):
        blanked = [t for t in atom.named_tokens if not _PLAIN_WORD_RE.fullmatch(t.strip("`"))]
        text = blank_named(atom.plain_text, blanked)
        known.update(w.lower() for w in WORD_RE.findall(text))
    return known


def _fresh(tail: list[str], known: set[str]) -> bool:
    """Whether `tail` holds a content word the author's line does not have."""
    return any(len(w) > 1 and w not in STOPWORDS and w != _NAMED and not word_forms(w) & known for w in tail)


def _placed_words(old_by_line: ByLine, pair: Pair) -> set[str]:
    """The words the author's line already holds where a scope phrase may reuse them: those that
    stand inside a prepositional phrase, within a few words after a preposition in the same clause
    (clauses cut as the rewrite's are, `_clauses`). A word only used as a verb's object is not among
    them when its sentence goes on to other clauses; the paired sentence, when it is one clause,
    gives all its words, since its one object is what the instruction is about. A code token that
    is one plain word (`except`) is a word of the line, as in `_known_words`."""
    placed: set[str] = set()
    for atom in old_by_line.get(pair.old.line, ()):
        placed.update(t.strip("`").lower() for t in atom.named_tokens if _PLAIN_WORD_RE.fullmatch(t.strip("`")))
        for clause in _clauses(atom):
            for i, word in enumerate(clause):
                if word in PHRASE_PREPOSITIONS:
                    placed.update(clause[i + 1 : i + 1 + _SCOPE_REACH])
    if not _SEGMENT_RE.search(pair.old_sentence):
        placed.update(w for clause in _clauses(pair.old) for w in clause)
    return placed | {f for w in placed for f in word_forms(w)}


def _phrase(tail: list[str]) -> list[str]:
    """`tail` up to the next preposition or conjunction: the words of the phrase a preposition opens."""
    for i, word in enumerate(tail):
        if word in _PHRASE_END:
            return tail[:i]
    return tail


def _cuts_coverage(word: str, tail: list[str], known: set[str]) -> bool:
    """Whether `word`, followed by `tail`, cuts the rule's coverage down in a way the author's line
    (`known`) did not already carry (`classify.COVERAGE_RESTRICTORS`)."""
    rule = COVERAGE_RESTRICTORS.get(word)
    if rule is None or rule.already & known:
        return False
    return not rule.next_words or bool(tail[:1]) and tail[0] in rule.next_words


def _narrows(words: list[str], known: set[str], placed: set[str]) -> bool:
    """Whether the rewrite's `words` add a restriction the author's line did not state: a
    restricting word it never used, a place / time / thing after a preposition that the author's
    sentence did not already hold inside a prepositional phrase (`placed`), or a new noun phrase
    after `for` (judged against every word of the line, `known`)."""
    for i, word in enumerate(words):
        tail = words[i + 1 : i + 1 + _SCOPE_REACH]
        if word in SCOPE_RESTRICTORS and word not in known:
            return True
        if _cuts_coverage(word, tail, known):
            return True
        if word in SCOPE_PREPOSITIONS and _fresh(_phrase(tail), placed):
            return True
        if word == "for" and tail[:1] and tail[0] in DETERMINERS and _fresh(tail, known):
            return True
    return False


def _clauses(atom: Any, *, named: bool = False) -> list[list[str]]:
    """`atom`'s words, one list per comma / colon / parenthesis separated clause, each named
    construct a placeholder word unless `named` (a condition's words read the same backticked or
    not)."""
    parts = _CLAUSE_RE.split(prose_text(atom, named=named, fill=f" {_NAMED} "))
    return [w for w in ([t.lower() for t in WORD_RE.findall(part)] for part in parts) if w]


def _line_named(old_by_line: ByLine, line: int) -> set[str]:
    """The named constructs (lowered, backticks stripped) the author's line holds."""
    return {named_key(t) for atom in old_by_line.get(line, ()) for t in atom.named_tokens}


def _quantifier_before(text: str, start: int) -> str:
    """The word that ends `text` before offset `start`, lowered; empty when there is none."""
    words = WORD_RE.findall(text[:start])
    return words[-1].lower() if words else ""


def _inserted_after_quantifier(p: Pair) -> bool:
    """Whether the rewrite names a construct the author's sentence did not, directly after a general
    quantifier the author's sentence already had (`any file` -> `any .env file`, or `any .env` in the
    place of `file`). A definite reference (`the gate` -> `the AskUserQuestion gate`) names its
    referent and narrows nothing."""
    text = p.new.plain_text
    known = {named_key(t) for t in p.old.named_tokens}
    old_words = {w.lower() for w in WORD_RE.findall(p.old.plain_text)}
    for token in p.new.named_tokens:
        if named_key(token) in known:
            continue
        for match in re.finditer(re.escape(token.strip("`")), text):
            quantifier = _quantifier_before(text, match.start())
            if quantifier in GENERAL_QUANTIFIERS & old_words:
                return True
    return False


def _same_sentence(p: Pair) -> bool:
    """Whether the rewrite's sentence is the author's, word for word (spacing and case aside)."""
    return " ".join(p.old_sentence.lower().split()) == " ".join(p.new_sentence.lower().split())


def narrowed_instructions(pairs: list[Pair], old_by_line: ByLine) -> list[dict[str, Any]]:
    """Each matched instruction whose rewrite adds words that restrict where, when or to what it
    applies, without an if / when / before frame (which `added_conditions` already reports): a
    restricting word the line never used, or a scope preposition whose phrase holds a word the
    author's sentence did not already hold inside a prepositional phrase (`define WHAT to build` ->
    `define WHAT to build in that spec`, though `spec` is elsewhere on the line); or one that
    names a construct directly after a general quantifier the author's line already had (`every
    gate` -> `every X gate`)."""
    out: list[dict[str, Any]] = []
    for p in pairs:
        if _same_sentence(p):
            continue
        known = _known_words(old_by_line, p.old.line)
        known |= {f for w in known for f in word_forms(w)}
        placed = _placed_words(old_by_line, p)
        if any(_narrows(clause, known, placed) for clause in _clauses(p.new)) or _inserted_after_quantifier(p):
            out.append(p.entry())
    return out


def made_specific(
    pairs: list[Pair], old_by_line: ByLine, flagged: AbstractSet[tuple[int, int]], invented: AbstractSet[str]
) -> list[dict[str, Any]]:
    """Each kept instruction that gained a named construct the author's line lacked and that no
    other check flagged (`flagged` holds the `(line, new_line)` of narrowed pairs, `invented` the
    lowered names reported as invented): allowed and listed so the report can show it."""
    out: list[dict[str, Any]] = []
    for p in pairs:
        if (p.old.line, p.new.line) in flagged:
            continue
        known = _line_named(old_by_line, p.old.line) | invented
        if any(named_key(t) not in known for t in p.new.named_tokens):
            out.append({"line": p.old.line, "before": p.old_sentence, "after": p.new_sentence})
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
    if word_forms(word) & words:
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
    return {w for w in content_words(rewrite) - _CONDITION_WORDS if not word_forms(w) & original_words}


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
