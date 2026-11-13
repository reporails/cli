"""Wording of the matched instructions in the preservation check: a hedge made direct (listed), a
hedge made an absolute the line never had, words added to what an instruction covers, a condition
added, and a condition dropped.

Each reads what the mapper recorded on the atoms: `modality` for hedged and absolute, the slots
(`subject`, `predicate`, `object`, `scope`) for the words an instruction covers, and
`classify.condition_text` for a condition.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from collections.abc import Set as AbstractSet
from functools import cache

from reporails_cli.core.heal.preservation.coverage import (
    after_definite_modifier,
    covered_tokens,
    fresh_place,
    last_index,
    moved_before_head,
    names_a_place,
    quantified_insert,
    replaced,
    tail_after,
    took_no_object,
    words_of_named,
)
from reporails_cli.core.heal.preservation.kinds import (
    Section,
    heading_words,
    lists_kinds,
    named_beside_others,
    sections_by_line,
)
from reporails_cli.core.heal.preservation.words import (
    AtomView,
    atom_words,
    is_content_word,
    named_key,
    slot_words,
    token_words,
)
from reporails_cli.core.mapper.classify import ABSOLUTE_CUES, condition_text
from reporails_cli.core.mapper.classify_lexicon import (
    CONDITION_CONJUNCTIONS,
    CONDITIONAL_MARKERS,
    LIMITING_RESTRICTORS,
    SUBJECT_PRONOUNS,
    words_of,
)
from reporails_cli.core.mapper.lexical import word_forms
from reporails_cli.core.mapper.prose_split import split_prose_sentences
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.heal import Pair, SnapshotAtom
from reporails_cli.core.platform.dto.ruleset import Atom

_NEUTRAL_COVERAGE = 0.75  # share of a new instruction's words a hedged line the mapper read as prose must hold

# Atoms of a file by line number, in file order.
ByLine = dict[int, list[AtomView]]


def by_line(atoms: Iterable[AtomView]) -> ByLine:
    """`atoms` bucketed by line number, in the order given."""
    out: ByLine = {}
    for atom in atoms:
        out.setdefault(atom.line, []).append(atom)
    return out


def sentence_of(atoms_by_line: ByLine, atom: AtomView) -> str:
    """The sentence of `atom`'s line that holds it (the line's atoms joined, cut by the mapper's
    sentence splitter); the whole line when none does."""
    line = " ".join(a.text for a in atoms_by_line.get(atom.line, ())) or atom.text
    needle = atom.text.strip().lower()[:15]
    for sentence in split_prose_sentences(line, atom.named_tokens):
        if needle and needle in sentence.lower():
            return sentence
    return line


def continuation(line_atoms: Sequence[AtomView], atom: AtomView) -> tuple[str, ...]:
    """The words, in order, of the uncharged atoms that continue the prohibition `atom` on its line,
    from the mapper's atoms of that line: those that follow it before the next charged one (`Do not
    file any plan —` and the `release notes, build work, or hub notes — into the hub.` after it,
    while a directive after the dash, `prefer a fake`, is no part of it). Empty when `atom` is not
    a constraint."""
    start = next((i for i, a in enumerate(line_atoms) if a is atom), None)
    if start is None or atom.charge_value != -1:
        return ()
    words: list[str] = []
    for a in line_atoms[start + 1 :]:
        if a.charge_value != 0:
            break
        words.extend(token_words(a.plain_text.split()))
    return tuple(words)


def pair_up(
    snap_atoms: list[SnapshotAtom], matched_new_for: dict[int, Atom], old_by_line: ByLine, new_by_line: ByLine
) -> list[Pair]:
    """Each matched instruction as a `Pair`."""
    out = []
    for sa in snap_atoms:
        match = matched_new_for.get(id(sa))
        if sa.charge_value != 0 and match is not None:
            more = continuation(new_by_line.get(match.line, ()), match)
            out.append(Pair(sa, match, sentence_of(old_by_line, sa), sentence_of(new_by_line, match), more))
    return out


def made_direct(
    pairs: list[Pair],
    snap_atoms: list[SnapshotAtom],
    new_atoms: list[Atom],
    matched_new_for: dict[int, Atom],
    sentences: tuple[ByLine, ByLine],
) -> list[JsonObject]:
    """Each instruction whose original was a suggestion (`prefer`, `consider`, `should`, `try`, ...)
    and whose rewrite is not: the change is allowed and listed with the sentence before and after,
    so the report can show it. A rewritten instruction with no matched original counts when its
    words come from a hedged line the mapper read as plain prose (`You might want to run the
    linter`)."""
    out: list[JsonObject] = []
    seen: set[tuple[int, int]] = set()
    done: set[int] = set()
    for p in pairs:
        key = (p.old.line, p.new.line)
        if (
            key not in seen
            and p.old.modality == "hedged"
            and p.new.modality != "hedged"
            and p.old_sentence != p.new_sentence
        ):
            seen.add(key)
            done.add(p.old.line)
            out.append(p.entry())
    return out + _made_direct_from_prose(snap_atoms, new_atoms, matched_new_for, done, sentences)


def _made_direct_from_prose(
    snap_atoms: list[SnapshotAtom],
    new_atoms: list[Atom],
    matched_new_for: dict[int, Atom],
    done: set[int],
    sentences: tuple[ByLine, ByLine],
) -> list[JsonObject]:
    old_by_line, new_by_line = sentences
    claimed = {id(m) for m in matched_new_for.values()}
    hedged_prose = [sa for sa in snap_atoms if sa.charge_value == 0 and not sa.heading and sa.modality == "hedged"]
    out: list[JsonObject] = []
    for na in new_atoms:
        words = atom_words(na)
        if na.charge_value == 0 or id(na) in claimed or not words:
            continue
        for sa in hedged_prose:
            if sa.line in done or len(words & atom_words(sa)) / len(words) < _NEUTRAL_COVERAGE:
                continue
            done.add(sa.line)
            out.append(Pair(sa, na, sentence_of(old_by_line, sa), sentence_of(new_by_line, na)).entry())
            break
    return out


def hedge_made_absolute(pairs: list[Pair], old_by_line: ByLine) -> list[JsonObject]:
    """Each matched suggestion whose rewrite is an absolute where no atom of the author's line is, or
    holds an absolute cue."""
    return [
        p.entry()
        for p in pairs
        if p.old.modality == "hedged"
        and p.new.modality == "absolute"
        and not any(_absolute(a) for a in old_by_line.get(p.old.line, ()))
    ]


def _absolute(atom: AtomView) -> bool:
    """Whether `atom` is absolute, or carries an absolute cue the mapper's hedge reading outranked
    (`You should always run X` reads hedged)."""
    return atom.modality == "absolute" or not ABSOLUTE_CUES.isdisjoint(words_of(atom.plain_text))


def _same_sentence(p: Pair) -> bool:
    """Whether the rewrite's sentence is the author's, word for word (spacing and case aside)."""
    return " ".join(p.old_sentence.lower().split()) == " ".join(p.new_sentence.lower().split())


def _known_words(old_by_line: ByLine, p: Pair) -> set[str]:
    """The words the author's instruction has, each with its singular and plural spelling: for a
    prohibition its own plain text and the uncharged atoms that continue it (a word only a
    neighbouring instruction has is not among them), for any other instruction every atom of its
    line."""
    atoms = old_by_line.get(p.old.line, ())
    if p.old.charge_value < 0:
        known = set(words_of(p.old.plain_text)) | set(continuation(atoms, p.old))
    else:
        known = {w for atom in atoms for w in words_of(atom.plain_text)}
    return known | {f for w in known for f in word_forms(w)}


def _heading(p: Pair, section: Section) -> list[str]:
    """The words of the heading `p`'s original sits under: its section's heading atom, else the heading
    the mapper gave the atom."""
    return heading_words(section) or words_of(p.old.heading_context)


def _kind_narrows(p: Pair, kind: list[str], span: list[str], section: Section) -> bool:
    """Whether words given to an instruction whose verb took no object narrow it: they are a list
    (`span`, from the first to the last of them, holds an `and` / `or`), the section's heading lists
    kinds and `kind` is one of them, or another line of the section names `kind` beside others.
    A kind nothing else names is the referent the line left implied."""
    if CONDITION_CONJUNCTIONS & set(span):
        return True
    heading = _heading(p, section)
    forms = {f for w in heading for f in word_forms(w)}
    if lists_kinds(heading) and all(w in forms for w in kind):
        return True
    return named_beside_others(section, p.old, kind)


def _gained_unsafe(p: Pair, known: set[str], heading: set[str]) -> list[int]:
    """The indices of the rewrite's covered words that are content words the author's instruction lacks
    and that no safe shape explains (a possessive, `the user's`, names the owner it points at). The words
    themselves are in `covered_tokens(p)`."""
    covered = covered_tokens(p)
    gained = [
        i
        for i, (w, _c, _s, prose) in enumerate(covered)
        if is_content_word(w) and prose and not word_forms(w) & known and not w.endswith("'s")
    ]
    if not gained:
        return []
    old_object = slot_words(p.old, "object")
    anchor = last_index(covered, old_object[-1]) if old_object else None
    widened = set(tail_after(covered, anchor)) if anchor is not None else set()
    own_named = words_of_named(p.old)
    skip = widened | replaced(covered, p, gained)
    pool = set(gained)
    return [
        i
        for i in gained
        if i not in skip
        and covered[i][0] not in heading
        and not (i > 0 and covered[i - 1][0] in own_named)
        and not (old_object and after_definite_modifier(covered, pool, i, old_object[-1]))
        and not names_a_place(covered, i)
    ]


def _scope_gains_construct(p: Pair) -> bool:
    """Whether the rewrite's scope names a target (`for src/`) the author's instruction does not name."""
    tokens = [t.lower() for t in slot_tokens(p.new, "scope")]
    scope = " ".join(tokens[tokens.index("for") :]) if "for" in tokens else ""
    old = {named_key(t) for t in p.old.named_tokens}
    return any(named_key(t) in scope and named_key(t) not in old for t in p.new.named_tokens)


def _narrows(p: Pair, known: set[str], section: Section) -> bool:
    """Whether the rewrite's object or scope gains a content word the author's instruction lacks that
    is no safe shape: an alternative after the author's own object (`secrets` -> `secrets or
    credentials`, which widens), a construct named after a general quantifier (`any file` -> `any
    .env file`), a word of the section heading that names one referent, a word after a named
    construct the author's instruction names (`signal` -> `signal artifact`), a modifier of the
    referent a definite determiner points at (`the API` -> `the REST API`), the words that describe
    a place a named construct gives (`the install notes at setup.md`), or a reword that puts new
    words where author words left. A suggestion is not narrowed by its own wording, nor an
    instruction whose object the author gave as a bare pronoun. An object given to a verb that took
    none is read against the section (`_kind_narrows`). Any other shape is put back."""
    old_object = slot_words(p.old, "object")
    if p.new.modality == "hedged" or (old_object and all(w in SUBJECT_PRONOUNS for w in old_object)):
        return False
    if quantified_insert(p) or moved_before_head(p) or _scope_gains_construct(p):
        return True
    heading = _heading(p, section)
    referent = set() if lists_kinds(heading) else {f for w in heading for f in word_forms(w)}
    unsafe = _gained_unsafe(p, known, referent)
    if not unsafe:
        return fresh_place(p, covered_tokens(p))
    if took_no_object(p.old):
        covered = covered_tokens(p)
        span = [w for w, _c, _s, _p in covered[unsafe[0] : unsafe[-1] + 1]]
        return _kind_narrows(p, [covered[i][0] for i in unsafe], span, section)
    return True


def narrowed_instructions(pairs: list[Pair], old_by_line: ByLine) -> list[JsonObject]:
    """Each matched instruction whose rewrite gains, in its object or scope slot (and, for a
    prohibition, in the uncharged atoms that continue it), a content word the author's own
    instruction does not have, unless the gain is a safe shape (`_narrows`). An unknown shape is put
    back: the default is narrowed."""
    sections = sections_by_line(old_by_line)
    return [
        p.entry()
        for p in pairs
        if not _same_sentence(p) and _narrows(p, _known_words(old_by_line, p), sections.get(p.old.line, []))
    ]


def made_specific(
    pairs: list[Pair], old_by_line: ByLine, flagged: AbstractSet[tuple[int, int]], invented: AbstractSet[str]
) -> list[JsonObject]:
    """Each kept instruction that gained a named construct the author's line lacked and that no
    other check flagged (`flagged` holds the `(line, new_line)` of narrowed pairs, `invented` the
    lowered names reported as invented): allowed and listed so the report can show it, once per
    sentence of the author's, with every sentence its rewrite became (a split shows all its pieces)."""
    rewrites: dict[tuple[int, str], dict[str, None]] = {}
    for p in pairs:
        rewrites.setdefault((p.old.line, p.old_sentence), {})[p.new_sentence] = None
    out: list[JsonObject] = []
    listed: set[tuple[int, str]] = set()
    for p in pairs:
        key = (p.old.line, p.old_sentence)
        if (p.old.line, p.new.line) in flagged or key in listed:
            continue
        known = {named_key(t) for atom in old_by_line.get(p.old.line, ()) for t in atom.named_tokens} | invented
        if any(named_key(t) not in known for t in p.new.named_tokens):
            listed.add(key)
            out.append({"line": p.old.line, "before": p.old_sentence, "after": " ".join(rewrites[key])})
    return out


def conditional(atom: AtomView) -> bool:
    """Whether the mapper read a conditional frame on `atom`."""
    return atom.scope_conditional


_ARTICLES = DEFINITE_DETERMINERS | INDEFINITE_ARTICLES
_ENDING_REACH = 4  # letters an ending may add to a word and still be that word


@cache
def _marker_words() -> frozenset[str]:
    """The words that only mark a condition or a quantifier over it: swapping one marker for another
    (`every time` -> `whenever`, `prior to` -> `before`) adds no content of its own."""
    return frozenset(w for marker in CONDITIONAL_MARKERS for w in marker.split())


def _condition_words(atom: AtomView) -> frozenset[str] | None:
    """The content words of the condition the mapper read on `atom` (`classify.condition_text`),
    markers and function words left out; None when it read none."""
    text = condition_text(atom)
    if text is None:
        return None
    return frozenset(w for w in words_of(text) if is_content_word(w) and w not in _marker_words())


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


def dropped_conditions(pairs: list[Pair]) -> list[JsonObject]:
    """Each matched instruction whose original holds a condition that its rewrite no longer holds:
    the words of the original's condition are not all in the rewrite's condition (`If the build
    fails, run X before Y` rewritten `Run X before Y` has none of `build` and `fails`), or the
    rewrite has no condition, or the rewrite's condition names a word the original's lacks (`If the
    build passes` for `If the build fails`; an `only` condition may name more of its limit). A condition
    restated with its marker swapped or another form of its words is held."""
    out = []
    for p in pairs:
        governed = _condition_words(p.old)
        if not governed:
            continue
        rewrite = _condition_words(p.new)
        if (
            rewrite is None
            or not all(_is_word_of(w, rewrite) for w in governed)
            or (not _limiting(p.old) and not all(_is_word_of(w, governed) for w in rewrite))
        ):
            out.append(p.entry())
    return out


def _opening_scope(line_atoms: Sequence[AtomView]) -> frozenset[str]:
    """The words of the scope phrase the line's first instruction opens with (`For all,`); empty when it has none."""
    first = next((a for a in line_atoms if a.charge_value != 0), None)
    if first is None or first.slots is None or first.slots.scope_span is None or first.slots.scope_span[0] != 0:
        return frozenset()
    return frozenset(w for w in slot_words(first, "scope") if w not in _ARTICLES)


def _sentence_scope(new_by_line: ByLine, p: Pair) -> frozenset[str]:
    """The words of the scope phrases of the rewrite's atoms that sit in the sentence holding `p.new`."""
    sentence = p.new_sentence.lower()
    atoms = [a for a in new_by_line.get(p.new.line, ()) if a is p.new or a.text.strip().lower() in sentence]
    return frozenset(w for a in atoms for w in slot_words(a, "scope"))


def dropped_scopes(pairs: list[Pair], sentences: tuple[ByLine, ByLine]) -> list[JsonObject]:
    """Each matched instruction on a line that opens with a scope phrase (`For all, do A, do B`) whose
    rewrite's sentence does not hold that scope: a split that leaves a sentence outside the scope the
    original opened with."""
    old_by_line, new_by_line = sentences
    out = []
    for p in pairs:
        opening = _opening_scope(old_by_line.get(p.old.line, ()))
        if opening:
            held = _sentence_scope(new_by_line, p)
            if not all(_is_word_of(w, held) for w in opening):
                out.append(p.entry())
    return out


def _limiting(atom: AtomView) -> bool:
    """Whether the condition the mapper read on `atom` holds a limiting word (`only`)."""
    text = condition_text(atom)
    return text is not None and bool(set(words_of(text)) & LIMITING_RESTRICTORS)


def added_conditions(snap_atoms: list[SnapshotAtom], matched_new_for: dict[int, Atom]) -> list[JsonObject]:
    """Each matched instruction that was not conditional, whose rewrite is conditional and carries
    a content word the author's line never had in its condition or its object (every snapshot atom on that line
    counts as the author's line; singular and plural forms are the same word, and words that only
    mark a condition are not content). A rewrite that restates the author's own condition in other
    words, or spreads it over several lines, is not listed."""
    out: list[JsonObject] = []
    for sa in snap_atoms:
        match = matched_new_for.get(id(sa))
        if sa.charge_value == 0 or match is None or sa.scope_conditional:
            continue
        words = _condition_words(match)
        if words is not None:
            words = words | {w for w in slot_words(match, "object") if is_content_word(w)}
        known = {w for other in snap_atoms if other.line == sa.line for w in words_of(other.plain_text)}
        if words and any(not word_forms(w) & known for w in words):
            out.append({"line": sa.line, "text": sa.text, "new_line": match.line, "new_text": match.text})
    return out
