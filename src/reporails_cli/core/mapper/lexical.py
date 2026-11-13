"""Embedding-free text helpers for the mapper: cutting a sentence into clauses, and the spellings of a word.

- ``split_clauses`` — marker-based clause splitter: strong markers (em/en-dash,
  ``;`` ``:``) cut between clauses, and a coordinating (``, and/but/or/then``) or
  subordinating (``before/after/when/…``) marker cuts just ahead of its own word,
  which stays on the clause it introduces rather than disappearing with the cut.
"""

from __future__ import annotations

import re

# The em dash and the en dash, which set a clause off from the one before it.
DASH_MARKS = frozenset({chr(0x2014), chr(0x2013)})

# What opens a list or a closing clause: a colon, or a dash set off by spaces.
OPENER_RE = re.compile(":|\\s[" + "".join(sorted(DASH_MARKS)) + "]\\s")

# ── Clause-split markers ───────────────────────────────────────────────
# STRONG markers: space-flanked em/en-dash, semicolon, colon. Punctuation only, so
# consuming the marker itself loses no word.
_STRONG_RE = re.compile(r"\s+[" + "".join(sorted(DASH_MARKS)) + r"]\s+|;\s+|:\s+")
# COORD / SUBORD markers are WORDS (`and`, `before`, …): the cut sits on the whitespace
# just ahead of the marker (a lookahead, not a capture), so the marker word itself opens
# the clause that follows rather than being consumed by the split.
_COORD_RE = re.compile(r",\s+(?=(?:and|but|or|then)\s)", re.IGNORECASE)
_SUBORD_RE = re.compile(
    r"\s+(?=(?:before|after|when|while|unless|until|although|because|rather than|instead of)\s)",
    re.IGNORECASE,
)


def split_items(text: str) -> list[str]:
    """`text` cut at its commas outside parentheses, the commas dropped (`a (b, c), d` -> `['a (b, c)', ' d']`)."""
    depth, start, out = 0, 0, []
    for i, ch in enumerate(text):
        depth += (ch == "(") - (ch == ")")
        if ch == "," and depth <= 0:
            out.append(text[start:i])
            start = i + 1
    return [*out, text[start:]]


def word_forms(word: str) -> set[str]:
    """`word` with its plain singular and plural spellings (`test` / `tests`, `match` / `matches`)."""
    forms = {word, word + "s", word + "es"}
    if word.endswith("es"):
        forms.add(word[:-2])
    if word.endswith("s"):
        forms.add(word[:-1])
    return forms


def split_clauses(text: str) -> list[str]:
    """Split a sentence into clauses at marker boundaries.

    Applies the STRONG, then COORD, then SUBORD marker sets in sequence and
    drops fragments shorter than three characters. Returns the whole text as a
    single clause when no marker fires.
    """
    parts = _STRONG_RE.split(text)
    parts = [seg for chunk in parts for seg in _COORD_RE.split(chunk)]
    parts = [seg for chunk in parts for seg in _SUBORD_RE.split(chunk)]
    clauses = [seg.strip() for seg in parts if len(seg.strip()) >= 3]
    return clauses or [text.strip()]
