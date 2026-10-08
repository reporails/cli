"""Word-level reading shared by the preservation checks: the content words of an instruction
(stopwords and hedges left out), a prose atom's words with its named constructs removed, and the
negation cue.
"""

from __future__ import annotations

import re
from typing import Any

from reporails_cli.core.mapper.classify import HEDGE_WORDS, NEGATION_WORDS

WORD_RE = re.compile(r"[a-zA-Z0-9_']+")

# Common English function words, dropped from content-word coverage: polarity already tracks
# negation/modality (`charge_value`), so these words would only pad an overlap between two
# otherwise-unrelated instructions without adding topic signal.
STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "and",
        "or",
        "but",
        "nor",
        "of",
        "to",
        "in",
        "on",
        "at",
        "for",
        "with",
        "by",
        "from",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "this",
        "that",
        "these",
        "those",
        "it",
        "its",
        "as",
        "not",
        "no",
        "never",
        "always",
        "do",
        "does",
        "did",
        "will",
        "would",
        "should",
        "can",
        "could",
        "may",
        "might",
        "must",
        "shall",
        "when",
        "if",
        "than",
        "then",
        "so",
        "before",
        "after",
        "into",
        "onto",
        "up",
        "down",
        "out",
        "over",
        "under",
        "again",
        "once",
        "here",
        "there",
        "all",
        "each",
        "few",
        "more",
        "most",
        "other",
        "some",
        "such",
        "only",
        "own",
        "too",
        "very",
        "just",
        "also",
        "per",
        "you",
        "your",
        "any",
        "every",
        "one",
    }
)

# Hedge words and `please` are dropped from content words too: a rewrite removes them.
_SKIPPED = STOPWORDS | HEDGE_WORDS | {"please"}

# A negation cue: the `n't` contraction suffix, or a standalone negation word (the classifier's
# negation words, and `without`).
NEGATION_RE = re.compile(
    r"n't\b|\b(?:" + "|".join(sorted((NEGATION_WORDS - {"n't"}) | {"without"})) + r")\b",
    re.IGNORECASE,
)


def content_words(text: str) -> set[str]:
    """`text`'s content words: stopwords, hedges/filler, and short tokens dropped, the rest lowered."""
    return {w for w in (t.lower() for t in WORD_RE.findall(text)) if len(w) > 2 and w not in _SKIPPED}


def named_key(token: str) -> str:
    """A named token's comparison key: backticks stripped, lowered."""
    return token.strip("`").lower()


def blank_named(text: str, tokens: Any, fill: str = " ") -> str:
    """`text` with each named token (backticks stripped) blanked, or replaced by `fill`, the longest
    first so a token inside a longer one (`reporails` in `reporails__explain`) leaves none of the
    longer one behind."""
    for token in sorted((t.strip("`") for t in tokens), key=len, reverse=True):
        if token:
            text = text.replace(token, fill)
    return text


def prose_text(atom: Any, *, named: bool = False, fill: str = " ") -> str:
    """`atom`'s plain text with its named constructs (backticked in the source) blanked out (or
    replaced by `fill`), or kept when `named` (a word reads the same backticked or not)."""
    text: str = atom.plain_text
    return text if named else blank_named(text, atom.named_tokens, fill)


def prose_words(atom: Any, *, named: bool = False) -> list[str]:
    """`atom`'s lowered words in order, its named constructs left out unless `named`."""
    return [w.lower() for w in WORD_RE.findall(prose_text(atom, named=named))]


def word_forms(word: str) -> set[str]:
    """`word` with its plain singular and plural spellings (`test` / `tests`, `match` / `matches`)."""
    forms = {word, word + "s", word + "es"}
    if word.endswith("es"):
        forms.add(word[:-2])
    if word.endswith("s"):
        forms.add(word[:-1])
    return forms
