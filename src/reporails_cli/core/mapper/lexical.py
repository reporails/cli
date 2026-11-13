"""Embedding-free text helpers for the mapper: cutting a sentence at its marks, its list items and
its clauses, and reading its words (`prose_tokens`, `word_forms`, `list_tokens`, `is_list_item`).

- ``split_clauses`` — marker-based clause splitter: strong markers (em/en-dash,
  ``;`` ``:``) cut between clauses, and a coordinating (``, and/but/or/then``) or
  subordinating (``before/after/when/…``) marker cuts just ahead of its own word,
  which stays on the clause it introduces rather than disappearing with the cut.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from collections.abc import Set as AbstractSet

from reporails_cli.core.mapper.classify_lexicon import (
    CLAUSE_JOINERS,
    CLAUSE_OPENING_VERBS,
    CODE_WORD_RE,
    COMMA,
    LIST_SEPARATORS,
    SEE_ASIDE_RE,
    STOPWORDS,
    TOKEN_EDGES,
)
from reporails_cli.core.mapper.md_parser import replace_code_spans

# The em dash and the en dash, which set a clause off from the one before it.
DASH_MARKS = frozenset({"\u2014", "\u2013"})

# Marks that end a phrase: a comma, `;`, `:`, a parenthesis or a dash.
PHRASE_MARKS = COMMA + ";:()" + "".join(sorted(DASH_MARKS))
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


def split_at_marks(text: str, marks: str = PHRASE_MARKS) -> list[str]:
    """`text` cut at every one of the characters `marks`, which are dropped; the pieces keep their
    spacing and may be empty (`a, (b)` -> `['a', ' ', 'b', '']`). More than one piece means a mark stood."""
    return re.split("[" + re.escape(marks) + "]", text)


def split_items(text: str) -> list[str]:
    """`text` cut at its commas outside parentheses, the commas dropped (`a (b, c), d` -> `['a (b, c)', ' d']`)."""
    depth, start, out = 0, 0, []
    for i, ch in enumerate(text):
        depth += (ch == "(") - (ch == ")")
        if ch == COMMA and depth <= 0:
            out.append(text[start:i])
            start = i + 1
    return [*out, text[start:]]


def prose_tokens(sentence: str) -> list[str]:
    """The lowered whitespace tokens of `sentence` outside code spans, a hyphenated word kept whole
    (`ready-for-review` holds no `for`), a `(see ...)` reference aside left out."""
    text = SEE_ASIDE_RE.sub(" ", replace_code_spans(sentence, " code "))
    return [t.strip(TOKEN_EDGES).lower() for t in text.split()]


def word_forms(word: str) -> set[str]:
    """`word` with its plain singular and plural spellings (`test` / `tests`, `match` / `matches`)."""
    forms = {word, word + "s", word + "es"}
    if word.endswith("es"):
        forms.add(word[:-2])
    if word.endswith("s"):
        forms.add(word[:-1])
    return forms


def is_content_word(word: str) -> bool:
    """Whether `word` is longer than two letters and not a function word."""
    return len(word) > 2 and word not in STOPWORDS


def list_tokens(text: str) -> list[str]:
    """The lowered content words of `text` in order, with a `,` kept where one stood and `and` / `or`
    kept as separators, except an `and` that joins clauses (`CLAUSE_JOINERS`, followed by a verb:
    `Build docs and push`), which separates no items."""
    tokens: list[str] = []
    for i, part in enumerate(text.lower().split(COMMA)):
        if i:
            tokens.append(COMMA)
        words = CODE_WORD_RE.findall(part)
        for k, w in enumerate(words):
            joins_clauses = w in CLAUSE_JOINERS and words[k + 1 : k + 2] and words[k + 1] in CLAUSE_OPENING_VERBS
            if not joins_clauses and (w in LIST_SEPARATORS or is_content_word(w)):
                tokens.append(w)
    return tokens


def phrase_starts(tokens: Sequence[str], phrase: Sequence[str]) -> list[int]:
    """Where `phrase` (content words, any singular / plural form) stands in `tokens`, as start indices."""
    n = len(phrase)
    return [k for k in range(len(tokens) - n + 1) if all(tokens[k + d] in word_forms(w) for d, w in enumerate(phrase))]


def is_list_item(
    tokens: Sequence[str],
    phrase: Sequence[str],
    *,
    before: AbstractSet[str] = LIST_SEPARATORS,
    after: AbstractSet[str] = LIST_SEPARATORS,
) -> bool:
    """Whether `phrase` stands as an item of a coordinated list in `tokens` (`list_tokens` of a text;
    `Lint Python, shell, or Docker`): a separator stands right before it (one of `before`) or right
    after it (one of `after`)."""
    for k in phrase_starts(tokens, phrase):
        end = k + len(phrase)
        if (k > 0 and tokens[k - 1] in before) or (end < len(tokens) and tokens[end] in after):
            return True
    return False


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
