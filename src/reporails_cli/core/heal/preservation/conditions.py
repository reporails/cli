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

from reporails_cli.core.heal.preservation.words import (
    AtomView,
    atom_words,
    is_content_word,
    is_function_word,
    named_key,
    prose_text,
    slot_prose_tokens,
    slot_tokens,
    token_words,
)
from reporails_cli.core.mapper.classify import condition_text
from reporails_cli.core.mapper.classify_lexicon import (
    CONDITION_CONJUNCTIONS,
    CONDITIONAL_MARKERS,
    DEFINITE_DETERMINERS,
    LIMITING_RESTRICTORS,
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
    """Each matched suggestion whose rewrite is an absolute where no atom of the author's line is."""
    return [
        p.entry()
        for p in pairs
        if p.old.modality == "hedged"
        and p.new.modality == "absolute"
        and not any(a.modality == "absolute" for a in old_by_line.get(p.old.line, ()))
    ]


def _same_sentence(p: Pair) -> bool:
    """Whether the rewrite's sentence is the author's, word for word (spacing and case aside)."""
    return " ".join(p.old_sentence.lower().split()) == " ".join(p.new_sentence.lower().split())


def _line_words(old_by_line: ByLine, line: int) -> set[str]:
    """The words the author's line has, each with its singular and plural spelling."""
    atoms = old_by_line.get(line, ())
    # The author's prose words, and each construct they named that is one word (`try`): a rewrite
    # that writes it without backticks has said nothing new.
    known = {w for atom in atoms for w in words_of(prose_text(atom))}
    known |= {named_key(t) for atom in atoms for t in atom.named_tokens if words_of(t) == [named_key(t)]}
    return known | {f for w in known for f in word_forms(w)}


def _covered_tokens(p: Pair) -> list[tuple[str, bool]]:
    """What the rewrite's instruction covers, in order, as `(word, a comma follows it)`: the words of
    its object and scope slots, then those of the uncharged atoms that continue it when it is a
    prohibition. A scope that is a condition the author's instruction lacked is left to
    `added_conditions`."""
    if p.new.slots is None:
        tokens = prose_text(p.new).split()
    else:
        added_condition = condition_text(p.new) is not None and condition_text(p.old) is None
        tokens = slot_prose_tokens(p.new, "object") + ([] if added_condition else slot_prose_tokens(p.new, "scope"))
    out = [(w, token.endswith(",")) for token in tokens for w in token_words([token])]
    return out + [(w, False) for w in p.continued]


def _tail_after(covered: list[tuple[str, bool]], anchor: int) -> range:
    """The indices of the alternatives an `or` / `and` list adds after `covered[anchor]`: empty
    unless a conjunction (or a comma) follows the word at once; the list runs through the
    conjunction to the end of the phrase."""
    nxt = covered[anchor + 1][0] if anchor + 1 < len(covered) else ""
    if nxt not in CONDITION_CONJUNCTIONS and not covered[anchor][1]:
        return range(0)
    stop = len(covered)
    conj = next((k for k in range(anchor + 1, len(covered)) if covered[k][0] in CONDITION_CONJUNCTIONS), None)
    if conj is not None:
        stop = next(
            (k for k in range(conj + 1, len(covered)) if is_function_word(covered[k][0])),
            len(covered),
        )
    return range(anchor + 1, stop)


def _last_index(covered: list[tuple[str, bool]], word: str) -> int | None:
    """The last index of `word`, in a singular or plural spelling, in `covered`."""
    forms = word_forms(word)
    return max((i for i, (w, _comma) in enumerate(covered) if w in forms), default=None)


def _after_definite(covered: list[tuple[str, bool]], at: int, named: set[str]) -> bool:
    """Whether the named construct word at `covered[at]` follows a definite determiner, directly or
    through the other words of its own construct."""
    k = at - 1
    while k >= 0 and covered[k][0] in named:
        k -= 1
    return k >= 0 and covered[k][0] in DEFINITE_DETERMINERS


def _narrows(p: Pair, known: set[str]) -> bool:
    """Whether the rewrite's object or scope gains a content word the author's line lacks that is no
    safe shape: an alternative after the author's own object (`secrets` -> `secrets or credentials`,
    which widens), a word of the section heading (the referent it names) or a named construct directly
    after a definite determiner (`the gate` -> `the AskUserQuestion gate`)."""
    covered = _covered_tokens(p)
    gained = [i for i, (w, _comma) in enumerate(covered) if is_content_word(w) and not word_forms(w) & known]
    if not gained:
        return False
    object_words = [w for token in slot_tokens(p.old, "object") for w in token_words([token])]
    anchor = _last_index(covered, object_words[-1]) if object_words else None
    widened = set(_tail_after(covered, anchor)) if anchor is not None else set()
    heading = {f for w in words_of(p.old.heading_context) for f in word_forms(w)}
    named = {w for t in p.new.named_tokens for w in words_of(t)}
    return any(
        i not in widened
        and covered[i][0] not in heading
        and not (covered[i][0] in named and _after_definite(covered, i, named))
        for i in gained
    )


def narrowed_instructions(pairs: list[Pair], old_by_line: ByLine) -> list[JsonObject]:
    """Each matched instruction whose rewrite gains, in its object or scope slot (and, for a
    prohibition, in the uncharged atoms that continue it), a content word the author's line does not
    have anywhere, unless the gain is a safe shape (`_narrows`). An unknown shape is put back: the
    default is narrowed."""
    return [p.entry() for p in pairs if not _same_sentence(p) and _narrows(p, _line_words(old_by_line, p.old.line))]


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


def _limiting(atom: AtomView) -> bool:
    """Whether the condition the mapper read on `atom` is opened by a limiting word (`only`)."""
    text = condition_text(atom)
    return text is not None and bool(set(words_of(text)[:1]) & LIMITING_RESTRICTORS)


def added_conditions(snap_atoms: list[SnapshotAtom], matched_new_for: dict[int, Atom]) -> list[JsonObject]:
    """Each matched instruction that was not conditional, whose rewrite is conditional and carries
    a content word the author's line never had in its condition (every snapshot atom on that line
    counts as the author's line; singular and plural forms are the same word, and words that only
    mark a condition are not content). A rewrite that restates the author's own condition in other
    words, or spreads it over several lines, is not listed."""
    out: list[JsonObject] = []
    for sa in snap_atoms:
        match = matched_new_for.get(id(sa))
        if sa.charge_value == 0 or match is None or sa.scope_conditional:
            continue
        words = _condition_words(match)
        known = {w for other in snap_atoms if other.line == sa.line for w in words_of(other.plain_text)}
        if words and any(not word_forms(w) & known for w in words):
            out.append({"line": sa.line, "text": sa.text, "new_line": match.line, "new_text": match.text})
    return out
