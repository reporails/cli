"""The classifier's word sets are the only spelling of negation, hedge and absolute words."""

from __future__ import annotations

import pytest

from reporails_cli.core.heal.preservation.match import _leading_polarity_sign
from reporails_cli.core.mapper.classify import (
    _ABSOLUTE_ADVERBS,
    ABSOLUTE_CUES,
    AFFIRMATIVE_ABSOLUTES,
    NEGATION_WORDS,
    has_negation_cue,
)


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize("word", sorted(NEGATION_WORDS))
def test_every_classifier_negation_word_is_a_preservation_cue(word: str) -> None:
    assert has_negation_cue(f"it {word}" if word != "n't" else "it don't")


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_without_stays_a_preservation_cue() -> None:
    assert has_negation_cue("run it without flags")


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
