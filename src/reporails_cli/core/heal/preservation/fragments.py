"""Dangling fragments in the preservation check: a sentence of the rewrite that is what a split
left behind. The author's sentence opened a list or a closing clause with a colon or a dash and
carried on past its first comma; the rewrite keeps the lead-in with only that first item
(`...: you read the intent.`, `... intent — ask.`) and the rest stands elsewhere or is gone. A
sentence that ends partway through a comma series of two or more items, without closing it with
`and` / `or`, while the author's series went on, is left behind the same way. A colon or dash
inside a code span opens nothing, and an item that begins with `then` is a next step, not a list item.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence

from reporails_cli.core.heal.preservation.words import AtomView, is_content_word
from reporails_cli.core.mapper.classify_lexicon import CLAUSE_JOINERS, STEP_JOINER, words_of
from reporails_cli.core.mapper.lexical import DASH_MARKS, OPENER_RE, split_items, word_forms
from reporails_cli.core.mapper.markers import without_list_marker
from reporails_cli.core.mapper.md_parser import replace_code_spans
from reporails_cli.core.mapper.parse import inline_plain_text
from reporails_cli.core.mapper.prose_split import ends_with_sentence_mark, split_prose_sentences
from reporails_cli.core.platform.contract.json_value import JsonObject

_TRIM = " \t.;:"

# Stand-ins for the opener marks inside a code span, so a colon or a dash there opens nothing.
_STAND_INS = {mark: chr(0xE000 + i) for i, mark in enumerate((":", *sorted(DASH_MARKS)))}
_MASK = str.maketrans(_STAND_INS)
_UNMASK = {stand_in: mark for mark, stand_in in _STAND_INS.items()}


def _masked(content: str) -> str:
    """`content` (a code span's text) with its opener marks replaced by stand-ins."""
    return content.translate(_MASK)


def _unmasked(text: str) -> str:
    """`text` with the stand-ins put back."""
    for mark, original in _UNMASK.items():
        text = text.replace(mark, original)
    return text


def _masked_plain(text: str) -> str:
    """`text` read as plain text with the opener marks inside its code spans masked."""
    return inline_plain_text(replace_code_spans(text, lambda span: _masked(text[span.start : span.end])))


def _plain(atom: AtomView) -> str:
    """The atom's plain text with the opener marks inside its code spans masked: each span is masked
    where it stands in the atom's marked-up text, then the markup is read away. An atom whose plain
    text is not its inline reading (a heading, a fenced block) keeps its own."""
    text: str = atom.text
    if inline_plain_text(text) != atom.plain_text:
        return str(atom.plain_text)
    return _masked_plain(text)


def _normal(text: str) -> str:
    """`text` lowered with its spacing collapsed and trailing marks trimmed."""
    return " ".join(text.lower().split()).strip(_TRIM)


def _bare(item: str) -> str:
    """`item` normalised, without a leading `and` / `or`."""
    text = _normal(item)
    for joiner in ("and ", "or "):
        text = text.removeprefix(joiner)
    return text


def _openers(text: str) -> Iterable[tuple[str, str]]:
    """Each `(lead-in with its opener, what follows)` split of `text`."""
    for match in OPENER_RE.finditer(text):
        yield text[: match.end()], text[match.end() :]


def _items_after(old_text: str, lead: str) -> list[str]:
    """The items the author's sentence gives after `lead`, cut at commas; empty when it lacks `lead`."""
    start = " ".join(old_text.lower().split()).find(" ".join(lead.lower().split()))
    if start < 0:
        return []
    return split_items(" ".join(old_text.split())[start + len(" ".join(lead.split())) :])


def _carries(new_sentences: list[str], lead: str, item: str) -> bool:
    """Whether a sentence of the rewrite repeats `lead` with `item` after it."""
    return any(
        _normal(nl) == _normal(lead) and _normal(nt) == _bare(item) for new in new_sentences for nl, nt in _openers(new)
    )


def _next_step(item: str) -> bool:
    """Whether `item` begins with `then`: a next step, not one more item of a list."""
    return _normal(item).startswith("then ")


def _cut_short(old_text: str, lead: str, new_tail: str, new_sentences: list[str]) -> bool:
    """Whether the author's sentence holds `lead` followed by a list or clause that runs on past
    its first comma, `new_tail` is only that first item, and a later item is not carried in the
    rewrite by a sentence that repeats `lead`."""
    first, *later = _items_after(old_text, lead) or [""]
    if not later or not _normal(new_tail) or _normal(new_tail) != _normal(first) or _next_step(later[0]):
        return False
    return not all(_carries(new_sentences, lead, item) for item in later)


def _held(words: set[str], sentence_words: set[str]) -> bool:
    """Whether every one of `words` is in `sentence_words`, as a word or its plain plural."""
    return all(word_forms(w) & sentence_words for w in words)


def _shares(words: set[str], sentence_words: set[str]) -> bool:
    """Whether some of `words` is in `sentence_words`, as a word or its plain plural."""
    return any(word_forms(w) & sentence_words for w in words)


def _words_of(text: str) -> set[str]:
    """The lowered words of `text`."""
    return set(words_of(text))


def content_words(text: str) -> set[str]:
    """The content words of `text`: longer than two letters and not a function word."""
    return {w for w in words_of(text) if is_content_word(w)}


def _rephrased_cut(old_text: str, new_text: str, new_sentences: list[str]) -> bool:
    """Whether `new_text` holds the content words of the lead-in of the author's sentence and of
    its first item but of no later item, while a later item stands in no sentence of the rewrite
    that holds the lead-in (the lead-in rephrased, the first item hung off it, the rest split off)."""
    mine = _words_of(new_text)
    for lead, tail in _openers(old_text):
        first, *later = split_items(tail)
        if later and _next_step(later[0]):
            continue
        lead_words = content_words(lead)
        first_words = content_words(first) - lead_words
        if not lead_words or not first_words or not (_held(lead_words, mine) and _shares(first_words, mine)):
            continue
        later_words = [content_words(i) - lead_words - first_words for i in later]
        if not any(later_words) or _shares(set().union(*later_words), mine):
            continue
        leads = [w for n in new_sentences if _held(lead_words, w := _words_of(n))]
        if not all(any(_shares(words, w) for w in leads) for words in later_words if words):
            return True
    return False


def _wholes(atoms: Sequence[AtomView]) -> list[str]:
    """Each atom's sentence in full: an atom ending in a comma is joined with the atoms that
    follow it on the same line."""
    out = []
    for i, atom in enumerate(atoms):
        text, j = _plain(atom), i + 1
        while text.rstrip().endswith(",") and j < len(atoms) and atoms[j].line == atom.line:
            text, j = f"{text} {_plain(atoms[j])}", j + 1
        out.append(text)
    return out


_HALF = 0.5  # share of an item's content words a rewrite item must hold to stand for it


def _stands_for(old_item: str, new_item: str) -> bool:
    """Whether `new_item` holds at least half the content words of `old_item`."""
    words = content_words(old_item)
    mine = _words_of(new_item)
    return bool(words) and sum(1 for w in words if word_forms(w) & mine) / len(words) >= _HALF


def _series_cut(old_text: str, new: str, new_sentences: list[str]) -> bool:
    """Whether the rewrite sentence `new` holds the first k >= 2 items of the comma series of the
    author's sentence `old_text` (items cut outside parentheses, an item held when the rewrite item
    keeps at least half its content words), the series goes on past item k, `new` holds none of the
    later items and does not close its own list with `and` / `or`, and, when the series opens
    after a lead-in, a later item is not carried by a rewrite sentence that repeats the lead-in.
    Only a series the author closed with `and` / `or` counts: one that runs on with `then`, or has
    no closing conjunction, is no list to cut short."""
    old_items, new_items = split_items(old_text), split_items(new)
    k = len(new_items)
    if k < 2 or len(old_items) <= k or _bare(old_items[-1]) == _normal(old_items[-1]) or _next_step(old_items[k]):
        return False
    if _bare(new_items[-1]) != _normal(new_items[-1]):
        return False
    if not all(_stands_for(o, n) for o, n in zip(old_items, new_items, strict=False)):
        return False
    kept = set().union(*(content_words(i) for i in old_items[:k]))
    mine = _words_of(new)
    for item in old_items[k:]:
        fresh = content_words(item) - kept
        if fresh and sum(1 for w in fresh if word_forms(w) & mine) / len(fresh) >= _HALF:
            return False
    for lead, _ in _openers(old_text):
        if _normal(old_items[0]).startswith(_normal(lead)):
            return not all(_carries(new_sentences, lead, item) for item in old_items[k:])
    return True


def _lead_stands_alone(old_text: str, new: str, new_sentences: list[str]) -> bool:
    """Whether the rewrite sentence `new` is exactly the author's sentence up to an opener, whole
    and carrying none of the items after it, and every one of those items stands in a sentence of
    the rewrite of its own: a lead-in kept as a complete sentence, each item split off as one more
    (`... deliberate intent — ask, don't refactor.` -> `... deliberate intent. Ask ... Do not
    refactor ...`), which is no fragment."""
    rest = set().union(*(_words_of(n) for n in new_sentences if n is not new))
    for match in OPENER_RE.finditer(old_text):
        if _normal(old_text[: match.start()]) != _normal(new):
            continue
        words = [content_words(i) for i in split_items(old_text[match.end() :])]
        if any(words) and all(_shares(w, rest) for w in words if w):
            return True
    return False


_LEAD_JOINERS = CLAUSE_JOINERS - {STEP_JOINER}


def _step_at(words: list[str], i: int) -> str | None:
    """What the step that `words[i]` opens goes on to say: `then` or `then,` followed by a word;
    None when `words[i]` opens none."""
    if i >= len(words) or words[i].removesuffix(",") != STEP_JOINER or i + 1 >= len(words):
        return None
    return " ".join(words[i + 1 :])


def _step_body(sentence: str) -> str | None:
    """What a sentence that opens with `then`, `then,` or `and then` goes on to say; None for any other."""
    words = _normal(sentence).lstrip("- ").split()
    return _step_at(words, 1 if words and words[0] in _LEAD_JOINERS else 0)


def opens_step(text: str) -> bool:
    """Whether `text` opens with `then`, `then,` or `and then`: a step that goes on from the one before it."""
    return _step_body(text) is not None


def _continues(whole: str, body: str) -> bool:
    """Whether the author's sentence `whole` carries on into the step `body` after something, with
    `then`, `then,` or `and then` (not at the start of a sentence)."""
    words = _normal(whole).split()
    for i in range(len(words)):
        start = i - 1 if i > 0 and words[i - 1] in _LEAD_JOINERS else i
        if (_step_at(words, i) or "").startswith(body) and start > 0 and words[start - 1][-1:] not in ".!?:":
            return True
    return False


def _marks(sentences: list[str], opens: list[bool], follows: list[bool]) -> list[tuple[str | None, bool, bool]]:
    """Each sentence's step body (if it opens with `then`), whether it opens its line and whether it
    follows a sentence that ended on its line."""
    return [(_step_body(s), o, f) for s, o, f in zip(sentences, opens, follows, strict=True)]


def _atom_marks(atoms: Sequence[AtomView], sentences: list[str]) -> list[tuple[str | None, bool, bool]]:
    """`_marks` for the atoms of a file, each sentence read with the line and the atom before it."""
    opens = [i == 0 or atoms[i - 1].line != a.line for i, a in enumerate(atoms)]
    follows = [not o and ends_with_sentence_mark(_plain(atoms[i - 1])) for i, o in enumerate(opens)]
    return _marks(sentences, opens, follows)


def _line_marks(sentences: list[str]) -> list[tuple[str | None, bool, bool]]:
    """`_marks` for the sentences of one line."""
    return _marks(sentences, [i == 0 for i in range(len(sentences))], [i > 0 for i in range(len(sentences))])


def _step_cuts(
    wholes: list[str], old: list[tuple[str | None, bool, bool]], new: list[tuple[str | None, bool, bool]]
) -> dict[int, int]:
    """Each sentence of the rewrite that is a step cut off its sentence, with the index of the author's
    sentence it was cut from. A rewrite sentence that opens with `then` right after a sentence of its line
    and goes on with a step the author carried on into inside one sentence is a cut, past as many as the
    author already wrote as sentences of their own (opening a line, or after a sentence that ended)."""
    written = Counter(body for body, opens, follows in old if body and (opens or follows))
    seen: Counter[str] = Counter()
    cuts: dict[int, int] = {}
    for j, (body, _, follows) in enumerate(new):
        source = next((k for k, w in enumerate(wholes) if body and follows and _continues(w, body)), None)
        if source is None or body is None:
            continue
        seen[body] += 1
        if seen[body] > written[body]:
            cuts[j] = source
    return cuts


def _source_of_cut[T](new: str, olds: Sequence[T], wholes: list[str], new_sentences: list[str]) -> T | None:
    """The author's sentence the whole rewrite sentence `new` is what a split left behind of, when
    it is one: it keeps the lead-in verbatim with the first item, or rephrases it with the first
    item hung off it. A sentence the original also holds, word for word, is no cut."""
    if _normal(new) in {_normal(w) for w in wholes}:
        return None
    for old, whole in zip(olds, wholes, strict=True):
        if _lead_stands_alone(whole, new, new_sentences):
            continue
        if any(_cut_short(whole, lead, tail, new_sentences) for lead, tail in _openers(new)):
            return old
        if _rephrased_cut(whole, new, new_sentences) or _series_cut(whole, new, new_sentences):
            return old
    return None


def dangling_fragments(old_atoms: Iterable[AtomView], new_atoms: Iterable[AtomView]) -> list[JsonObject]:
    """Each whole sentence of the rewrite that keeps an original sentence's lead-in (up to a colon
    or a dash), verbatim or rephrased, with only the first item the original gave after it, where
    the original went on past a comma and its later items are not each given by a rewrite sentence
    that repeats the lead-in; and each whole sentence that ends partway through the original's
    comma series (its first two or more items, the rest elsewhere). Sentences are the mapper's
    atoms, a long comma list the mapper cut into clause atoms on one line rejoined on both sides."""
    olds = [a for a in old_atoms if a.plain_text]
    news = [a for a in new_atoms if a.plain_text]
    wholes, new_sentences = _wholes(olds), _wholes(news)
    steps = _step_cuts(wholes, _atom_marks(olds, wholes), _atom_marks(news, new_sentences))
    out: list[JsonObject] = []
    for i, (new, sentence) in enumerate(zip(news, new_sentences, strict=True)):
        old = olds[steps[i]] if i in steps else _source_of_cut(sentence, olds, wholes, new_sentences)
        if old is not None:
            text = new.text if sentence == _plain(new) else _unmasked(sentence)
            out.append({"line": old.line, "text": old.text, "new_line": new.line, "new_text": text})
    return out


def rewrite_cut(before: str, after: str) -> str:
    """What the line `after`, a rewrite of the line `before`, leaves behind of a split: `"step"` when a
    sentence opens with `then` where `before` carried on into that step within one sentence, `"fragment"`
    when a sentence is what a split left of a lead-in or a list (the same reading `dangling_fragments`
    gives whole files), `""` when neither."""
    whole = _masked_plain(without_list_marker(before))
    sentences = split_prose_sentences(_masked_plain(without_list_marker(after)), [])
    old = split_prose_sentences(whole, [])
    if _step_cuts([whole], _line_marks(old), _line_marks(sentences)):
        return "step"
    return "fragment" if any(_source_of_cut(n, [True], [whole], sentences) is not None for n in sentences) else ""
