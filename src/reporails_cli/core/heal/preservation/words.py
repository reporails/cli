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


def prose_text(atom: Any, *, named: bool = False) -> str:
    """`atom`'s plain text with its named constructs (backticked in the source) blanked out, or
    kept when `named` (a word reads the same backticked or not)."""
    text: str = atom.plain_text
    if named:
        return text
    for token in atom.named_tokens:
        text = text.replace(token.strip("`"), " ")
    return text


def prose_words(atom: Any, *, named: bool = False) -> list[str]:
    """`atom`'s lowered words in order, its named constructs left out unless `named`."""
    return [w.lower() for w in WORD_RE.findall(prose_text(atom, named=named))]
