"""Dangling fragments in the preservation check: a sentence of the rewrite that is what a split
left behind. The author's sentence opened a list or a closing clause with a colon or a dash and
carried on past its first comma; the rewrite keeps the lead-in with only that first item
(`...: you read the intent.`, `... intent — ask.`) and the rest stands elsewhere or is gone.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from reporails_cli.core.heal.preservation.words import WORD_RE, content_words, word_forms

# What opens a list or a closing clause: a colon, or a dash set off by spaces.
_OPENER_RE = re.compile(r":|\s[—\u2013-]\s")
_TRIM = " \t.;:*_"


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


def _cut_short(old_text: str, lead: str, new_tail: str, new_sentences: list[str]) -> bool:
    """Whether the author's sentence holds `lead` followed by a list or clause that runs on past
    its first comma, `new_tail` is only that first item, and a later item is not carried in the
    rewrite by a sentence that repeats `lead`."""
    first, *later = _items_after(old_text, lead) or [""]
    if not later or not _normal(new_tail) or _normal(new_tail) != _normal(first):
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
        text, j = atom.plain_text, i + 1
        while text.rstrip().endswith(",") and j < len(atoms) and atoms[j].line == atom.line:
            text, j = f"{text} {atoms[j].plain_text}", j + 1
        out.append(text)
    return out


def _source_of_cut(new: str, olds: list[Any], wholes: list[str], new_sentences: list[str]) -> Any | None:
    """The author's sentence the whole rewrite sentence `new` is what a split left behind of, when
    it is one: it keeps the lead-in verbatim with the first item, or rephrases it with the first
    item hung off it. A sentence the original also holds, word for word, is no cut."""
    if _normal(new) in {_normal(w) for w in wholes}:
        return None
    for old, whole in zip(olds, wholes, strict=True):
        if any(_cut_short(old.plain_text, lead, tail, new_sentences) for lead, tail in _openers(new)):
            return old
        if _rephrased_cut(whole, new, new_sentences):
            return old
    return None


def dangling_fragments(old_atoms: Iterable[Any], new_atoms: Iterable[Any]) -> list[dict[str, Any]]:
    """Each whole sentence of the rewrite that keeps an original sentence's lead-in (up to a colon
    or a dash), verbatim or rephrased, with only the first item the original gave after it, where
    the original went on past a comma and its later items are not each given by a rewrite sentence
    that repeats the lead-in. Sentences are the mapper's atoms, a long comma list the mapper cut
    into clause atoms on one line rejoined on both sides."""
    olds = [a for a in old_atoms if a.plain_text]
    news = [a for a in new_atoms if a.plain_text]
    wholes, new_sentences = _wholes(olds), _wholes(news)
    out: list[dict[str, Any]] = []
    for new, sentence in zip(news, new_sentences, strict=True):
        old = _source_of_cut(sentence, olds, wholes, new_sentences)
        if old is not None:
            text = new.text if sentence == new.plain_text else sentence
            out.append({"line": old.line, "text": old.text, "new_line": new.line, "new_text": text})
    return out
