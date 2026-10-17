"""Word coordinates of a text: the offsets an atom's slot spans index into."""

from __future__ import annotations

import re

_WORD_RE = re.compile(r"\S+")


def word_offsets(text: str) -> list[tuple[int, int]]:
    """Character offsets of each word in `text` — the word coordinates an atom's slot spans use."""
    return [(m.start(), m.end()) for m in _WORD_RE.finditer(text)]


def words_between(text: str, start: int, end: int) -> str:
    """`text` over words `[start, end)`; empty when the span falls outside the text."""
    words = word_offsets(text)
    if not 0 <= start < end <= len(words):
        return ""
    return text[words[start][0] : words[end - 1][1]]
