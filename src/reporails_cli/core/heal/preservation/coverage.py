"""What a rewritten instruction covers, read from the mapper's slots: the words of its object and
scope slots (and, for a prohibition, what no slot holds), each marked with the slot it sits in and
whether it is the author's prose, and the shapes of added words that narrow nothing or narrow it.
"""

from __future__ import annotations

from collections.abc import Sequence
from collections.abc import Set as AbstractSet

from reporails_cli.core.heal.preservation.words import (
    AtomView,
    asides_of,
    blank_named,
    is_content_word,
    is_function_word,
    named_key,
    slot_tokens,
    slot_words,
    token_words,
)
from reporails_cli.core.mapper.classify import condition_text
from reporails_cli.core.mapper.classify_lexicon import (
    CONDITION_CONJUNCTIONS,
    DEFINITE_DETERMINERS,
    GENERAL_QUANTIFIERS,
    PHRASE_PREPOSITIONS,
    SCOPE_PREPOSITIONS,
    words_of,
)
from reporails_cli.core.mapper.lexical import word_forms
from reporails_cli.core.platform.dto.heal import Pair

# One word an instruction covers: the word, whether a comma follows it, the slot it sits in, and
# whether it is the author's prose (a word of a named construct is not).
Covered = list[tuple[str, bool, str, bool]]


def _prose_flags(tokens: list[str], named: Sequence[str]) -> list[bool]:
    """For each whitespace token, whether it survives blanking the named constructs: a token that
    is a construct, or part of one, is not prose."""
    prose = blank_named(" ".join(tokens), named).split()
    out: list[bool] = []
    k = 0
    for token in tokens:
        here = k < len(prose) and prose[k] == token
        out.append(here)
        if k < len(prose) and (here or prose[k] in token):
            k += 1
    return out


def covered_tokens(p: Pair) -> Covered:
    """What the rewrite's instruction covers, in order: the words of its object and scope slots, then
    those of the uncharged atoms that continue it when it is a prohibition. A scope that is a
    condition the author's instruction lacked is left to `added_conditions`."""
    if p.new.slots is None:
        tokens = [("object", t) for t in p.new.plain_text.split()]
    else:
        added_condition = condition_text(p.new) is not None and condition_text(p.old) is None
        tokens = [("object", t) for t in slot_tokens(p.new, "object")]
        if not added_condition:
            tokens += [("scope", t) for t in slot_tokens(p.new, "scope")]
        if p.new.charge_value < 0:
            tokens += [("rest", t) for t in past_the_slots(p.new)]
    flags = _prose_flags([t for _n, t in tokens], p.new.named_tokens)
    out = [
        (w, t.endswith(","), name, prose)
        for (name, t), prose in zip(tokens, flags, strict=True)
        for w in token_words([t])
    ]
    return out + [(w, False, "continued", True) for w in p.continued]


def past_the_slots(atom: AtomView) -> list[str]:
    """The words of `atom`'s plain text after its last slot: what a prohibition says that no slot
    holds (`Do not use a mock - prefer a fake`, whose hyphen the mapper reads no clause break at)."""
    slots = atom.slots
    spans = [] if slots is None else [slots.object_span, slots.scope_span, slots.predicate_span]
    ends = [span[1] for span in spans if span is not None]
    start = max(ends, default=0)
    words = atom.plain_text.split()
    return [w for i, w in enumerate(words) if i >= start and not any(a <= i < b for a, b in asides_of(atom))]


def moved_before_head(p: Pair) -> bool:
    """Whether a prohibition's rewrite puts, before the noun the author's object opens with, a word
    the author's object had after it, right in front of that noun (`the docs - those are generated` ->
    `generated docs`): a word that qualified the object from aside now cuts what it covers."""
    old = slot_words(p.old, "object")
    new = slot_words(p.new, "object")
    named = words_of_named(p.old)
    head = next((i for i, w in enumerate(old) if is_content_word(w) and w not in named), None)
    if p.new.charge_value >= 0 or head is None:
        return False
    at = next((i for i, w in enumerate(new) if w in word_forms(old[head])), None)
    if at is None:
        return False
    behind = [*old[head + 1 :], *token_words(past_the_slots(p.old))]
    after = {f for w in behind if is_content_word(w) for f in word_forms(w)}
    return at > 0 and is_content_word(new[at - 1]) and new[at - 1] in after


def tail_after(covered: Covered, anchor: int) -> range:
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


def last_index(covered: Covered, word: str) -> int | None:
    """The last index of `word`, in a singular or plural spelling, in `covered`."""
    forms = word_forms(word)
    return max((i for i, (w, _comma, _slot, _prose) in enumerate(covered) if w in forms), default=None)


def words_of_named(atom: AtomView) -> set[str]:
    """The words of the constructs `atom` names."""
    return {w for t in atom.named_tokens for w in words_of(t)}


def quantified_insert(p: Pair) -> bool:
    """Whether the rewrite names a construct the author's instruction did not directly after a general
    quantifier the author's instruction already had (`any file` -> `any .env file`, or `any .env` in the
    place of `file`). A definite reference (`the gate` -> `the AskUserQuestion gate`) names its
    referent and narrows nothing."""
    words = words_of(p.new.plain_text)
    old_words = set(words_of(p.old.plain_text))
    own = {named_key(t) for t in p.old.named_tokens}
    for token in p.new.named_tokens:
        size = len(words_of(token))
        if named_key(token) in own or not size:
            continue
        for at in range(1, len(words) - size + 1):
            if words[at : at + size] == words_of(token) and words[at - 1] in GENERAL_QUANTIFIERS & old_words:
                return True
    return False


def after_definite_modifier(covered: Covered, gained: set[int], i: int, head: str) -> bool:
    """Whether the gained word at `i` is in a run of gained words right after a definite determiner
    that runs into `head`, the noun the author's object ends in (`the API` -> `the REST API`): it
    names the referent the determiner already points at."""
    start = i
    while start - 1 in gained:
        start -= 1
    end = i
    while end + 1 in gained:
        end += 1
    return (
        start > 0
        and covered[start - 1][0] in DEFINITE_DETERMINERS
        and end + 1 < len(covered)
        and covered[end + 1][0] in word_forms(head)
    )


def names_a_place(covered: Covered, at: int) -> bool:
    """Whether the word at `at` sits in a phrase that ends at a preposition followed by a named
    construct (`the install notes at setup.md`): it describes the place the construct names."""
    for k in range(at + 1, len(covered)):
        word = covered[k][0]
        if word in PHRASE_PREPOSITIONS:
            return k + 1 < len(covered) and not covered[k + 1][3]
        if word in CONDITION_CONJUNCTIONS or covered[k][1]:
            return False
    return False


def _slot_replaced(covered: Covered, p: Pair, gained: list[int], slot: str) -> set[int]:
    """The gained words of one slot of the rewrite, when the slot no longer holds a content word or a
    preposition the same slot of the author's instruction had."""
    here = {w for w, _comma, name, _prose in covered if name == slot}
    gone = [
        w
        for w in slot_words(p.old, slot)
        if (is_content_word(w) or w in PHRASE_PREPOSITIONS) and not word_forms(w) & here
    ]
    return {i for i in gained if covered[i][2] == slot} if gone else set()


def replaced(covered: Covered, p: Pair, gained: list[int]) -> set[int]:
    """The gained words that stand where author words left: in an object or scope slot of a
    directive's rewrite that no longer holds a content word or a preposition of the same slot of the
    author's instruction (`the time left on the job` -> `the remaining time on the job`, `against the
    output` -> `against the drafted release notes`), the slot's new words reword it."""
    if p.new.charge_value <= 0:
        return set()
    return _slot_replaced(covered, p, gained, "object") | _slot_replaced(covered, p, gained, "scope")


def _phrases_after(
    words: list[str], opens: AbstractSet[str], commas: list[bool], prose: list[bool] | None = None
) -> list[list[str]]:
    """The words after each word of `opens`, up to the next preposition, conjunction or comma; a word
    that is no prose (`prose` says so) is left out of the phrase."""
    out: list[list[str]] = []
    for k, word in enumerate(words):
        if word not in opens:
            continue
        phrase: list[str] = []
        for j in range(k + 1, len(words)):
            if words[j] in PHRASE_PREPOSITIONS or words[j] in CONDITION_CONJUNCTIONS:
                break
            if prose is None or prose[j]:
                phrase.append(words[j])
            if commas[j]:
                break
        out.append(phrase)
    return out


def fresh_place(p: Pair, covered: Covered) -> bool:
    """Whether the rewrite stands the instruction in a place (`in`, `on`, `at`, ...) built from words
    the author's instruction used but never in a prepositional phrase (`send the summary` -> `send the
    summary in that report`, where `report` was an object): the instruction no longer covers every
    place."""
    # A one-word construct (`try`) is a word of the author's prose; a longer one (`src/lint.toml`) is not.
    old_tokens = blank_named(p.old.plain_text, [t for t in p.old.named_tokens if len(words_of(t)) > 1]).split()
    old_words = [w for t in old_tokens for w in words_of(t)]
    old_commas = [t.endswith(",") for t in old_tokens for _w in words_of(t)]
    placed = {w for phrase in _phrases_after(old_words, PHRASE_PREPOSITIONS, old_commas) for w in phrase}
    placed |= {f for w in placed for f in word_forms(w)}
    words = [w for w, _c, _s, _p in covered]
    prose = [pr for _w, _c, _s, pr in covered]
    return any(
        not is_function_word(w) and w not in placed
        for phrase in _phrases_after(words, SCOPE_PREPOSITIONS, [c for _w, c, _s, _p in covered], prose)
        for w in phrase
    )


def took_no_object(old: AtomView) -> bool:
    """Whether the author's instruction names no object for its verb (`Edit at canonical paths`,
    whose phrase the mapper reads as scope)."""
    slots = old.slots
    return slots is not None and slots.predicate_span is not None and slots.object_span is None
