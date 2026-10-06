"""Synthetic sentence-splitter tests.

Made-up sentences, not drawn from any corpus, over the splitter's core
behaviours: a plain two-sentence boundary, a run with no boundary at all, an
abbreviation whose period does not end a sentence, and a dotted path/version
token whose internal periods stay protected.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.prose_split import split_prose_sentences


@pytest.mark.unit
@pytest.mark.subsys_map
def test_splits_at_a_plain_sentence_boundary() -> None:
    text = "Run the linter first. Then commit your change."
    assert split_prose_sentences(text) == [
        "Run the linter first.",
        "Then commit your change.",
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_no_boundary_returns_the_whole_text_unsplit() -> None:
    text = "Keep this instruction on one line"
    assert split_prose_sentences(text) == [text]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_abbreviation_period_does_not_split() -> None:
    text = "Ask Dr. Alvarez before changing the schema."
    assert split_prose_sentences(text) == [text]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_dotted_path_and_version_periods_do_not_split() -> None:
    text = "Edit config/settings.local.py to set v2.4.1. Restart the worker after."
    assert split_prose_sentences(text) == [
        "Edit config/settings.local.py to set v2.4.1.",
        "Restart the worker after.",
    ]
