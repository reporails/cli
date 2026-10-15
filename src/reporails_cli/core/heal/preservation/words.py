"""Word-level reading shared by the preservation checks: the content words of an instruction
(stopwords and hedges left out), a prose atom's words with its named constructs removed, and the
negation cue.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Protocol

from reporails_cli.core.mapper.classify import HEDGE_WORDS, NEGATION_WORDS
from reporails_cli.core.mapper.classify_lexicon import STOPWORDS
from reporails_cli.core.platform.dto.ruleset import AtomFormat, Modality

WORD_RE = re.compile(r"[a-zA-Z0-9_']+")

# Hedge words and `please` are dropped from content words too: a rewrite removes them.
_SKIPPED = STOPWORDS | HEDGE_WORDS | {"please"}

# A negation cue: the `n't` contraction suffix, or a standalone negation word (the classifier's
# negation words, and `without`).
NEGATION_RE = re.compile(
    r"n't\b|\b(?:" + "|".join(sorted((NEGATION_WORDS - {"n't"}) | {"without"})) + r")\b",
    re.IGNORECASE,
)


class AtomView(Protocol):
    """The fields of an atom the preservation checks read, shared by a mapper atom and a snapshotted one."""

    @property
    def line(self) -> int:
        """The 1-based line."""

    @property
    def text(self) -> str:
        """The atom's text as written."""

    @property
    def plain_text(self) -> str:
        """The text with its markup read away."""

    @property
    def named_tokens(self) -> Sequence[str]:
        """The backticked constructs it names."""

    @property
    def format(self) -> AtomFormat:
        """The atom's format."""

    @property
    def charge_value(self) -> int:
        """-1 constraint, 0 neutral, +1 directive."""

    @property
    def modality(self) -> Modality:
        """How firmly it is asked."""

    @property
    def scope_conditional(self) -> bool:
        """Whether a conditional frame governs it."""


def content_words(text: str) -> set[str]:
    """`text`'s content words: stopwords, hedges/filler, and short tokens dropped, the rest lowered."""
    return {w for w in (t.lower() for t in WORD_RE.findall(text)) if len(w) > 2 and w not in _SKIPPED}


def named_key(token: str) -> str:
    """A named token's comparison key: backticks stripped, lowered."""
    return token.strip("`").lower()


# Marks a blanked token until every token is done, so a shorter token never matches inside the fill.
_BLANKED = "\ue010"


def blank_named(text: str, tokens: Iterable[str], fill: str = " ") -> str:
    """`text` with each named token (backticks stripped) blanked, or replaced by `fill`, the longest
    first so a token inside a longer one (`reporails` in `reporails__explain`) leaves none of the
    longer one behind."""
    for token in sorted((t.strip("`") for t in tokens), key=len, reverse=True):
        if token:
            text = text.replace(token, _BLANKED)
    return text.replace(_BLANKED, fill)


def prose_text(atom: AtomView, *, named: bool = False, fill: str = " ") -> str:
    """`atom`'s plain text with its named constructs (backticked in the source) blanked out (or
    replaced by `fill`), or kept when `named` (a word reads the same backticked or not)."""
    text: str = atom.plain_text
    return text if named else blank_named(text, atom.named_tokens, fill)


def prose_words(atom: AtomView, *, named: bool = False) -> list[str]:
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
