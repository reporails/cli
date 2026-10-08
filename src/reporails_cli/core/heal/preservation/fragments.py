"""Dangling fragments in the preservation check: a sentence of the rewrite that is what a split
left behind. The author's sentence opened a list or a closing clause with a colon or a dash and
carried on past its first comma; the rewrite keeps the lead-in with only that first item
(`...: you read the intent.`, `... intent — ask.`) and the rest stands elsewhere or is gone. A
sentence that ends partway through a comma series of two or more items, without closing it with
`and` / `or`, while the author's series went on, is left behind the same way. A colon or dash
inside a code span opens nothing, and an item that begins with `then` is a next step, not a list item.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from reporails_cli.core.heal.preservation.words import WORD_RE, content_words, word_forms
from reporails_cli.core.mapper.md_parser import replace_code_spans
from reporails_cli.core.mapper.parse import inline_plain_text

# What opens a list or a closing clause: a colon, or a dash set off by spaces.
_OPENER_RE = re.compile(r":|\s[—\u2013-]\s")
_TRIM = " \t.;:*_"

# Stand-ins for the opener marks inside a code span, so a colon or a dash there opens nothing.
_MASK = str.maketrans({":": "\ue000", "\u2014": "\ue001", "\u2013": "\ue002"})
_UNMASK = {"\ue000": ":", "\ue001": "\u2014", "\ue002": "\u2013", "\ue003": "-"}
_LONE_DASH_RE = re.compile(r"(?<=\s)-(?=\s)")


def _masked(content: str) -> str:
    """`content` (a code span's text) with its opener marks replaced by stand-ins."""
    return _LONE_DASH_RE.sub("\ue003", content.translate(_MASK))


def _unmasked(text: str) -> str:
    """`text` with the stand-ins put back."""
    for mark, original in _UNMASK.items():
        text = text.replace(mark, original)
    return text


def _plain(atom: Any) -> str:
    """The atom's plain text with the opener marks inside its code spans masked: each span is masked
    where it stands in the atom's marked-up text, then the markup is read away. An atom whose plain
    text is not its inline reading (a heading, a fenced block) keeps its own."""
    text: str = atom.text
    if inline_plain_text(text) != atom.plain_text:
        return str(atom.plain_text)
    return inline_plain_text(replace_code_spans(text, lambda span: _masked(text[span.start : span.end])))


def _normal(text: str) -> str:
    """`text` lowered with its spacing collapsed and trailing marks trimmed."""
    return " ".join(text.lower().split()).strip(_TRIM)


def _items(tail: str) -> list[str]:
    """`tail` cut at its commas outside parentheses."""
    depth, start, out = 0, 0, []
    for i, ch in enumerate(tail):
        depth += (ch == "(") - (ch == ")")
        if ch == "," and depth <= 0:
            out.append(tail[start:i])
            start = i + 1
    return [*out, tail[start:]]


def _bare(item: str) -> str:
    """`item` normalised, without a leading `and` / `or`."""
    text = _normal(item)
    for joiner in ("and ", "or "):
        text = text.removeprefix(joiner)
    return text


def _openers(text: str) -> Iterable[tuple[str, str]]:
    """Each `(lead-in with its opener, what follows)` split of `text`."""
    for match in _OPENER_RE.finditer(text):
        yield text[: match.end()], text[match.end() :]


def _items_after(old_text: str, lead: str) -> list[str]:
    """The items the author's sentence gives after `lead`, cut at commas; empty when it lacks `lead`."""
    start = " ".join(old_text.lower().split()).find(" ".join(lead.lower().split()))
    if start < 0:
        return []
    return _items(" ".join(old_text.split())[start + len(" ".join(lead.split())) :])


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
    return {w.lower() for w in WORD_RE.findall(text)}


def _rephrased_cut(old_text: str, new_text: str, new_sentences: list[str]) -> bool:
    """Whether `new_text` holds the content words of the lead-in of the author's sentence and of
    its first item but of no later item, while a later item stands in no sentence of the rewrite
    that holds the lead-in (the lead-in rephrased, the first item hung off it, the rest split off)."""
    mine = _words_of(new_text)
    for lead, tail in _openers(old_text):
        first, *later = _items(tail)
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


def _wholes(atoms: list[Any]) -> list[str]:
    """Each atom's sentence in full: the mapper cuts a long comma list into clause atoms on one
    line, each but the last ending in its comma, so the clauses that follow are joined on."""
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
    old_items, new_items = _items(old_text), _items(new)
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
    for match in _OPENER_RE.finditer(old_text):
        if _normal(old_text[: match.start()]) != _normal(new):
            continue
        words = [content_words(i) for i in _items(old_text[match.end() :])]
        if any(words) and all(_shares(w, rest) for w in words if w):
            return True
    return False


def _source_of_cut(new: str, olds: list[Any], wholes: list[str], new_sentences: list[str]) -> Any | None:
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


def dangling_fragments(old_atoms: Iterable[Any], new_atoms: Iterable[Any]) -> list[dict[str, Any]]:
    """Each whole sentence of the rewrite that keeps an original sentence's lead-in (up to a colon
    or a dash), verbatim or rephrased, with only the first item the original gave after it, where
    the original went on past a comma and its later items are not each given by a rewrite sentence
    that repeats the lead-in; and each whole sentence that ends partway through the original's
    comma series (its first two or more items, the rest elsewhere). Sentences are the mapper's
    atoms, a long comma list the mapper cut into clause atoms on one line rejoined on both sides."""
    olds = [a for a in old_atoms if a.plain_text]
    news = [a for a in new_atoms if a.plain_text]
    wholes, new_sentences = _wholes(olds), _wholes(news)
    out: list[dict[str, Any]] = []
    for new, sentence in zip(news, new_sentences, strict=True):
        old = _source_of_cut(sentence, olds, wholes, new_sentences)
        if old is not None:
            text = new.text if sentence == _plain(new) else _unmasked(sentence)
            out.append({"line": old.line, "text": old.text, "new_line": new.line, "new_text": text})
    return out
