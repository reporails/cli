"""Embedding-free clause-splitting helpers for the mapper.

- ``split_clauses`` — marker-based clause splitter: strong markers (em/en-dash,
  ``;`` ``:``) cut between clauses, and a coordinating (``, and/but/or/then``) or
  subordinating (``before/after/when/…``) marker cuts just ahead of its own word,
  which stays on the clause it introduces rather than disappearing with the cut.
"""

from __future__ import annotations

import re

# The em dash and the en dash, which set a clause off from the one before it.
DASH_MARKS = frozenset({"\u2014", "\u2013"})

COMMA = ","
# Marks that end a phrase: a comma, `;`, `:`, a parenthesis or a dash.
PHRASE_MARKS = COMMA + ";:()" + "".join(sorted(DASH_MARKS))

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


def split_at_marks(text: str, marks: str = PHRASE_MARKS) -> list[str]:
    """`text` cut at every one of the characters `marks`, which are dropped; the pieces keep their
    spacing and may be empty (`a, (b)` -> `['a', ' ', 'b', '']`). More than one piece means a mark stood."""
    return re.split("[" + re.escape(marks) + "]", text)


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
