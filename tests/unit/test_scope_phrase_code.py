"""A word is code when the markdown parse's code span covers it, not when backticks are counted."""

import pytest

from reporails_cli.core.mapper.md_parser import code_spans
from reporails_cli.core.mapper.scope_phrase import _in_code


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_double_backtick_span_holding_a_backtick_ends_where_the_parser_ends_it() -> None:
    text = "Run ``a`b`` during each release."
    assert code_spans(text)[0].end == 11
    assert _in_code(text) == [False, True, False, False, False]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_an_unmatched_backtick_is_text() -> None:
    assert _in_code("Run a ` b during release.") == [False] * 5 + [False]
