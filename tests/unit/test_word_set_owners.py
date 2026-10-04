"""The classifier's word sets are the only spelling of negation, hedge and absolute words."""

from __future__ import annotations

import pytest

from reporails_cli.core.heal.preservation.match import _leading_polarity_sign
from reporails_cli.core.heal.preservation.words import NEGATION_RE
from reporails_cli.core.mapper.classify import (
    _ABSOLUTE_ADVERBS,
    _MODAL_HEDGED,
    ABSOLUTE_CUES,
    AFFIRMATIVE_ABSOLUTES,
    HEDGE_WORDS,
    NEGATION_WORDS,
)


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize("word", sorted(NEGATION_WORDS))
def test_every_classifier_negation_word_is_a_preservation_cue(word: str) -> None:
    assert NEGATION_RE.search(f"it {word}" if word != "n't" else "it don't")


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_without_stays_a_preservation_cue() -> None:
    assert NEGATION_RE.search("run it without flags")


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_modal_hedges_are_part_of_the_hedge_words() -> None:
    assert _MODAL_HEDGED <= HEDGE_WORDS


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_absolute_adverbs_derive_from_the_absolute_cues() -> None:
    assert ABSOLUTE_CUES - {"never"} == AFFIRMATIVE_ABSOLUTES
    assert AFFIRMATIVE_ABSOLUTES | {"only"} == _ABSOLUTE_ADVERBS


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize("opener", sorted(AFFIRMATIVE_ABSOLUTES))
def test_every_affirmative_absolute_opens_a_positive_polarity(opener: str) -> None:
    assert _leading_polarity_sign(f"{opener.capitalize()} run the tests") == 1


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_never_opens_a_negative_polarity() -> None:
    assert _leading_polarity_sign("Never run the tests") == -1
