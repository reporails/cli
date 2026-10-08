"""The cli's own sentence for each listed reason code."""

from __future__ import annotations

import re

import pytest

from reporails_cli.formatters.listed_reasons import _LISTED_REASONS, listed_reason_text


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_every_code_has_a_plain_sentence() -> None:
    for code, text in _LISTED_REASONS.items():
        assert text.endswith("."), code
        assert not re.search(r"\d", text), f"{code} carries a number"
        assert not re.search(r"model|compet|research|measur", text, re.IGNORECASE) or code == "unbacked", code


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_unknown_code_gets_a_neutral_fallback() -> None:
    assert listed_reason_text("not-a-code") == listed_reason_text("")
    assert listed_reason_text("not-a-code") not in _LISTED_REASONS.values()


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_the_cli_owned_codes_are_covered() -> None:
    assert {"excluded", "line-fragment", "config-file"} <= set(_LISTED_REASONS)
