"""Mutation-killing tests for the prose splitter's internal decision helpers.

The public `split_prose_sentences` corpus leaves the position-aware quotation
pairing, the abbreviation veto, and the protected-shape giveback under-pinned.
These tests exercise those helpers directly so each named injected bug reddens.
All expected values were taken from the real (unmutated) functions.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.prose_split import (
    _closes_quotation,
    _find_span,
    _is_abbrev,
    _is_vetoed,
    _mask_protected_shapes,
    _mask_single_sentence_quotes,
    _opens_quotation,
)


def _protected_mask(text: str) -> list[bool]:
    mask = [False] * len(text)
    _mask_protected_shapes(text, mask)
    return mask


# --- _opens_quotation (L276) ------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_opens_quotation_at_index_zero() -> None:
    """A quote at index 0 opens a quotation.

    Kills: L276 `i == 0 -> i != 0` (mutant reads text[-1] and returns False);
    L276 first `or -> and` (`(i==0 and ...) or ...` is False here).
    """
    assert _opens_quotation('"x"', 0) is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_opens_quotation_after_whitespace() -> None:
    """A quote preceded by whitespace opens a quotation.

    Kills: L276 second `or -> and` (`... or (isspace and in_set)` is False when
    the preceding space is not itself an opening delimiter).
    """
    assert _opens_quotation(' "y', 1) is True
    # And a quote glued to a letter does NOT open one (guards against always-True).
    assert _opens_quotation('a"b', 1) is False


# --- _closes_quotation (L282) -----------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_closes_quotation_before_whitespace() -> None:
    """A quote followed by whitespace closes a quotation.

    Kills: L282 both `or -> and` mutations — with a following space that is not a
    trailing-punctuation char, either `and` collapses the result to False.
    """
    assert _closes_quotation('x" y', 1) is True


# --- _find_span symmetric flag (L287) ---------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_find_span_skips_non_opening_inch_mark() -> None:
    """Position-aware pairing skips a `"` that cannot open (an inch mark).

    Kills: L287 `open_ch == close_ch -> !=` (mutant treats straight quotes as
    asymmetric, pairs naively, and returns the wrong span (3, 10)).
    """
    assert _find_span('a 5" and "ok" done', '"', '"', 0) == (9, 13)


# --- _mask_single_sentence_quotes (L365) ------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_single_sentence_quote_is_masked() -> None:
    """A one-sentence quotation is fully masked.

    Kills: L365 `mask[i] = True -> False` (mutant leaves the span unmasked).
    """
    text = '"hi there"'
    mask = [False] * len(text)
    _mask_single_sentence_quotes(text, mask)
    assert mask == [True] * len(text)


# --- _mask_protected_shapes (L332 + L328 giveback cluster) ------------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_protected_shape_masks_path_no_giveback() -> None:
    """A path not followed by a terminator is masked in full.

    Kills: L332 `mask[i] = True -> False` (nothing masked);
    L328 first `and -> or` (runs the giveback to end 0, masks nothing);
    L328 second `and -> or` (over-gives-back, masks only 'a/b').
    """
    assert _protected_mask("a/b.c d") == [True, True, True, True, True, False, False]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_protected_shape_gives_back_trailing_terminator_before_space() -> None:
    """A path's trailing '.' before a space is given back (unmasked) so it can end
    the sentence.

    Kills: L328 `or -> and` inside the giveback guard (mutant keeps the trailing
    '.' masked because `end >= len` is False here).
    """
    # index 6 is the trailing '.', which must be left unmasked.
    assert _protected_mask("a/b.sh. Go") == [
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        False,
        False,
        False,
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_protected_shape_gives_back_trailing_terminator_at_eol() -> None:
    """A path's trailing '.' at end-of-text is still given back.

    Kills: L328 `end >= len(text) -> end > len(text)` (mutant fails the boundary
    comparison at EOL and keeps the trailing '.' masked).
    """
    assert _protected_mask("a/b.sh.") == [True, True, True, True, True, True, False]


# --- _is_abbrev (L389, L391) ------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_abbrev_co_ends_sentence_before_capital() -> None:
    """`Co.` before a capitalized word ends the sentence (not an abbreviation here).

    Kills: L389 `tok in MAY_END or variant in MAY_END -> and` (mutant misses the
    capitalized `Co.` and falls through to the plain-abbrev table, returning True).
    """
    assert _is_abbrev("at Lazard Freres & Co.", " He sat on the boards") is False


@pytest.mark.unit
@pytest.mark.subsys_map
def test_abbrev_capitalized_title_is_abbreviation() -> None:
    """`Dr.` is an abbreviation via the case-sensitive table.

    Kills: L391 first `or -> and` (`(tok in _ABBREV and variant in _ABBREV) or
    INITIAL` = False here — `Dr.` is in _ABBREV but `dr.` is not, and no
    leading-initial applies). The second `or` is covered by the initial case below.
    """
    assert _is_abbrev("See Dr.", " Smith") is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_abbrev_single_letter_initial() -> None:
    """A lone capital-letter initial (`A.`) binds as a list label, not a boundary.

    Kills: L391 second `or -> and` — `... or variant in _ABBREV and INITIAL`
    parses as `A or (B and C)`, so only the trailing-initial term distinguishes
    it (tok and variant are both absent from _ABBREV here).
    """
    assert _is_abbrev("See A.", " Foo") is True


# --- _is_vetoed (L416, L425, L429) ------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_map
def test_vetoed_when_left_is_only_marks() -> None:
    """A terminator with nothing but marks to its left is vetoed (no sentence
    preceded it).

    Kills: L416 `return True -> return False` in the marks-only guard.
    """
    assert _is_vetoed("?!", "?!", 2) is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_vetoed_question_answered_in_parenthetical() -> None:
    """A `?` answered by a following parenthetical is one unit (vetoed).

    Kills: L425 `... or (term.endswith('?') and TERNARY) ...` flipped to `and`
    (mutant drops the question-answered-in-brackets gloss and un-vetoes).
    """
    assert _is_vetoed("Need it? (only if so)", "?", 8) is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_vetoed_ternary_question_operator() -> None:
    """A `?` whose branch is followed by ` : ` is a ternary operator (vetoed).

    Kills: L429 `... or (ELLIPSIS and ANSWER_FOLLOWS)` flipped to `and`
    (mutant drops the ternary veto clause and un-vetoes).
    """
    assert _is_vetoed("cond?a : b", "?", 5) is True
