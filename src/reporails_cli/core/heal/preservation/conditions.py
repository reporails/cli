"""Wording of the matched instructions in the preservation check: a hedge made direct (listed), a
hedge made an absolute the line never had, words added to what an instruction covers, a condition
added, and a condition dropped.

Each reads what the mapper recorded on the atoms: `modality` for hedged and absolute, the slots
(`subject`, `predicate`, `object`, `scope`) for the words an instruction covers, and
`classify.condition_text` for a condition.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from collections.abc import Set as AbstractSet
from functools import cache

from reporails_cli.core.heal.preservation.coverage import (
    Covered,
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
    asides_of,
    atom_words,
    is_content_word,
    is_function_word,
    is_word_of,
    named_key,
    slot_tokens,
    slot_words,
    token_words,
    word_forms,
)
from reporails_cli.core.mapper.classify import ABSOLUTE_CUES, condition_text, covers_predicate
from reporails_cli.core.mapper.classify_lexicon import (
    CONDITION_CONJUNCTIONS,
    CONDITIONAL_MARKERS,
    DEFINITE_DETERMINERS,
    INDEFINITE_ARTICLES,
    LIMITING_RESTRICTORS,
    SUBJECT_PRONOUNS,
    words_of,
)
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
    """Each matched suggestion whose rewrite is an absolute (`Never`, `Always`) carrying a cue word
    that no atom of the author's line has."""
    return [
        p.entry()
        for p in pairs
        if p.old.modality == "hedged"
        and p.new.modality == "absolute"
        and _absolute_cues(p.new) - {c for a in old_by_line.get(p.old.line, ()) for c in _absolute_cues(a)}
    ]


def _absolute_cues(atom: AtomView) -> frozenset[str]:
    """The absolute cue words (`always`, `never`) the atom's plain text holds, including those the
    mapper's hedge reading outranked (`You should always run X` reads hedged)."""
    return ABSOLUTE_CUES & frozenset(words_of(atom.plain_text))


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


def _listed_heads(atom: AtomView, known: set[str]) -> set[str]:
    """The lowered words that name the kind an aside of `atom` lists members of: the words right before
    an aside whose own content words the author's line already has (`placement field` in `any
    placement field (cluster, type, or location)`), back to the nearest function word."""
    words = atom.plain_text.split()
    heads: set[str] = set()
    for start, end in asides_of(atom):
        listed = {w for token in words[start:end] for w in words_of(token) if is_content_word(w)}
        if not listed or not all(word_forms(w) & known for w in listed):
            continue
        k = start - 1
        while k >= 0 and not words[k].endswith(","):
            own = words_of(words[k])
            if not own or is_function_word(own[0]):
                break
            heads.update(own)
            k -= 1
    return heads


def _gained_unsafe(p: Pair, covered: Covered, known: set[str], heading: set[str]) -> list[int]:
    """The indices of the rewrite's covered words that are content words the author's instruction lacks
    and that no safe shape explains (a possessive, `the user's`, names the owner it points at). The words
    themselves are in `covered`."""
    heads = _listed_heads(p.new, known)
    gained = [
        i
        for i, (w, _c, _s, prose) in enumerate(covered)
        if is_content_word(w) and prose and not word_forms(w) & known and not w.endswith("'s") and w not in heads
    ]
    if not gained:
        return []
    old_object = slot_words(p.old, "object")
    anchor = last_index(covered, old_object[-1]) if old_object else None
    widened = set(tail_after(covered, anchor)) if anchor is not None else set()
    own_named = words_of_named(p.old)
    new_named = words_of_named(p.new) if p.old.charge_value < 0 else None
    skip = widened | replaced(covered, p, gained)
    pool = set(gained)
    return [
        i
        for i in gained
        if i not in skip
        and covered[i][0] not in heading
        and not (i > 0 and covered[i - 1][0] in own_named)
        and not (old_object and after_definite_modifier(covered, pool, i, old_object[-1], new_named))
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
    covered = covered_tokens(p)
    unsafe = _gained_unsafe(p, covered, known, referent)
    if not unsafe:
        return fresh_place(p, covered)
    if took_no_object(p.old):
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


@cache
def _marker_words() -> frozenset[str]:
    """The words that only mark a condition or a quantifier over it: swapping one marker for another
    (`every time` -> `whenever`, `prior to` -> `before`) adds no content of its own."""
    return frozenset(w for marker in CONDITIONAL_MARKERS for w in marker.split())


def _condition_words(text: str | None) -> list[str] | None:
    """The words of a condition (`classify.condition_text`) in order, markers and function words left
    out; a short name (`CI`) is one. None when the atom has no condition."""
    if text is None:
        return None
    markers = _marker_words()
    return [w for w in words_of(text) if not is_function_word(w) and w not in markers]


def _only_leading_missing(governed: list[str], rewrite: AbstractSet[str]) -> bool:
    """Whether every word of `governed` the rewrite lacks comes before the first one it keeps: a
    pronoun stands for the subject phrase that opens a condition (`the build` -> `it`), never for a
    second condition that follows it."""
    kept = next((i for i, w in enumerate(governed) if is_word_of(w, rewrite)), len(governed))
    return all(is_word_of(w, rewrite) for w in governed[kept:])


def _condition_dropped(p: Pair) -> bool:
    """Whether the original's condition is no longer held by the rewrite (`dropped_conditions`)."""
    old_text, new_text = condition_text(p.old), condition_text(p.new)
    governed = _condition_words(old_text)
    if governed is None:
        return False
    rewrite = _condition_words(new_text)
    if rewrite is None:
        return True
    if not governed:
        return False
    held = set(rewrite)
    restated = not SUBJECT_PRONOUNS.isdisjoint(words_of(new_text or ""))
    if not (all(is_word_of(w, held) for w in governed) or (restated and _only_leading_missing(governed, held))):
        return True
    limiting = bool(set(words_of(old_text or "")) & LIMITING_RESTRICTORS)
    old_set = set(governed)
    return not limiting and not all(w in SUBJECT_PRONOUNS or is_word_of(w, old_set) for w in rewrite)


def dropped_conditions(pairs: list[Pair]) -> list[JsonObject]:
    """Each matched instruction whose original holds a condition that its rewrite no longer holds:
    the words of the original's condition are not all in the rewrite's condition (`If the build
    fails, run X before Y` rewritten `Run X before Y` has none of `build` and `fails`), or the
    rewrite has no condition (whatever the length of the original's condition words: `If in CI`), or
    the rewrite's condition names a word the original's lacks (`If the build passes` for `If the
    build fails`; an `only` condition may name more of its limit). A condition restated with its
    marker swapped or another form of its words is held, and a pronoun may stand for the subject
    phrase that opens the condition."""
    return [p.entry() for p in pairs if _condition_dropped(p)]


def _opening_scope(line_atoms: Sequence[AtomView]) -> frozenset[str]:
    """The words of the scope phrase the first instruction of `line_atoms` opens with (`For all,`); empty if none."""
    first = next((a for a in line_atoms if a.charge_value != 0), None)
    if first is None or first.slots is None or first.slots.scope_span is None or first.slots.scope_span[0] != 0:
        return frozenset()
    if covers_predicate(first.slots):
        return frozenset()  # the scope holds the clause as well as its frame: a condition, read as one
    return frozenset(w for w in slot_words(first, "scope") if w not in _ARTICLES)


def _in_sentence(atoms_by_line: ByLine, atom: AtomView, sentence: str) -> list[AtomView]:
    """The atoms on `atom`'s line that sit in `sentence`."""
    return [a for a in atoms_by_line.get(atom.line, ()) if a is atom or sentence_of(atoms_by_line, a) == sentence]


def dropped_scopes(pairs: list[Pair], sentences: tuple[ByLine, ByLine]) -> list[JsonObject]:
    """Each matched instruction whose original sentence opens with a scope phrase (`For all, do A, do B`)
    and whose rewrite's sentence does not hold that scope: a split that leaves a sentence outside the
    scope the original opened with. A sentence that opens with no scope phrase has none to lose."""
    old_by_line, new_by_line = sentences
    out = []
    for p in pairs:
        opening = _opening_scope(_in_sentence(old_by_line, p.old, p.old_sentence))
        if not opening:
            continue
        held = frozenset(w for a in _in_sentence(new_by_line, p.new, p.new_sentence) for w in slot_words(a, "scope"))
        if not all(is_word_of(w, held) for w in opening):
            out.append(p.entry())
    return out


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
        cond = _condition_words(condition_text(match))
        words = None if cond is None else {w for w in (*cond, *slot_words(match, "object")) if is_content_word(w)}
        known = {w for other in snap_atoms if other.line == sa.line for w in words_of(other.plain_text)}
        if words and any(not word_forms(w) & known for w in words):
            out.append({"line": sa.line, "text": sa.text, "new_line": match.line, "new_text": match.text})
    return out
