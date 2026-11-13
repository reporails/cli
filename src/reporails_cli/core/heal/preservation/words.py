"""Word-level reading shared by the preservation checks: an instruction's words as the mapper's
slots hold them, and a prose atom's text with its named constructs removed.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from collections.abc import Set as AbstractSet
from functools import cache
from typing import Protocol

from reporails_cli.core.mapper.classify import hedge_cue_words
from reporails_cli.core.mapper.classify_lexicon import (
    CLAUSE_JOINERS,
    CONDITION_CONJUNCTIONS,
    CONDITION_OPENERS,
    DEFINITE_DETERMINERS,
    DETERMINERS,
    GENERAL_QUANTIFIERS,
    INDEFINITE_ARTICLES,
    PHRASE_PREPOSITIONS,
    words_of,
)
from reporails_cli.core.mapper.lexical import word_forms
from reporails_cli.core.platform.dto.ruleset import AtomFormat, AtomSlots, Modality


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

    @property
    def heading_context(self) -> str:
        """The text of the heading its section sits under."""

    @property
    def negative_heading(self) -> bool:
        """Whether it is a heading that is a bare negative label."""

    @property
    def slots(self) -> AtomSlots | None:
        """The subject, predicate, object and scope the mapper read, as word spans of `plain_text`."""

    @property
    def aside_spans(self) -> tuple[tuple[int, int], ...]:
        """The word spans of `plain_text` that illustrate the instruction."""


_MIN_WORD = 3  # letters a word needs to be a content word

# Marks a blanked token until every token is done, so a shorter token never matches inside the fill.
_BLANKED = ""


def blank_named(text: str, tokens: Iterable[str]) -> str:
    """`text` with each named token blanked, the longest first so a token inside a longer one
    (`reporails` in `reporails__explain`) leaves none of the longer one behind."""
    for token in sorted(tokens, key=len, reverse=True):
        if token:
            text = text.replace(token, _BLANKED)
    return text.replace(_BLANKED, " ")


def slot_tokens(atom: AtomView, *names: str) -> list[str]:
    """The words of `plain_text`, as written and in order, that the spans of the slots `names`
    (`subject`, `predicate`, `object`, `scope`) of `atom` cover, less the words of its asides: a slot
    with no span adds none."""
    if atom.slots is None:
        return []
    words = atom.plain_text.split()
    out: list[str] = []
    for name in names:
        span = getattr(atom.slots, f"{name}_span")
        if span is not None and 0 <= span[0] < span[1] <= len(words):
            out.extend(words[i] for i in range(*span) if not any(start <= i < end for start, end in atom.aside_spans))
    return out


def token_words(tokens: Iterable[str]) -> list[str]:
    """The lowered words, in order, of each of `tokens`."""
    return [w for token in tokens for w in words_of(token)]


def slot_words(atom: AtomView, *names: str) -> list[str]:
    """The lowered words, in order, of the slots `names` of `atom`."""
    return token_words(slot_tokens(atom, *names))


def _hedge_cue(atom: AtomView) -> frozenset[str]:
    """The lowered words of the hedge cue `atom` opens with (`maybe`, `you should`): a hedge says how
    firmly the instruction is asked, not what it covers."""
    return frozenset(words_of(" ".join(atom.plain_text.split()[: hedge_cue_words(atom.plain_text)])))


def atom_words(atom: AtomView) -> frozenset[str]:
    """An atom's content words: the words of its four slots, less its hedge cue; an atom with none read
    contributes the words of its plain text less its named constructs."""
    words = slot_words(atom, "subject", "predicate", "object", "scope")
    return frozenset(words or words_of(prose_text(atom))) - _hedge_cue(atom)


def core_words(atom: AtomView) -> frozenset[str]:
    """An instruction's core: the words of its subject, predicate and object slots, less its hedge cue and
    without the scope that restricts it; an atom with none read contributes what `atom_words` does."""
    words = slot_words(atom, "subject", "predicate", "object")
    return frozenset(words) - _hedge_cue(atom) if words else atom_words(atom)


@cache
def _function_words() -> frozenset[str]:
    """The mapper's function words: determiners, quantifiers, prepositions, conjunctions, condition
    openers."""
    return (
        DETERMINERS
        | DEFINITE_DETERMINERS
        | INDEFINITE_ARTICLES
        | GENERAL_QUANTIFIERS
        | PHRASE_PREPOSITIONS
        | CONDITION_CONJUNCTIONS
        | CLAUSE_JOINERS
        | CONDITION_OPENERS
    )


def is_function_word(word: str) -> bool:
    """Whether `word` is one of the mapper's function words."""
    return word in _function_words()


def is_content_word(word: str) -> bool:
    """Whether `word` is longer than two letters and not a function word."""
    return len(word) >= _MIN_WORD and not is_function_word(word)


_ENDING_REACH = 4  # letters an ending may add to a word and still be that word


def is_word_of(word: str, words: AbstractSet[str]) -> bool:
    """Whether `word` is one of `words`, in a plain singular / plural form or with a short ending
    added or dropped (`edit` / `editing`)."""
    if word_forms(word) & words:
        return True
    for other in words:
        short, long_ = sorted((word, other), key=len)
        shared = len(os.path.commonprefix([short, long_]))
        if shared >= max(3, len(short) - 1) and len(long_) - len(short) <= _ENDING_REACH:
            return True
    return False


def named_key(token: str) -> str:
    """A named token's comparison key: lowered."""
    return token.lower()


def prose_text(atom: AtomView) -> str:
    """`atom`'s plain text with its named constructs (backticked in the source) blanked out."""
    return blank_named(atom.plain_text, atom.named_tokens)
