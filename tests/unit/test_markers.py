"""`core/mapper/markers.py` — projecting a parent line's formatting back onto its spans."""

from __future__ import annotations

from typing import Any

import pytest

from reporails_cli.core.mapper import md_parser
from reporails_cli.core.mapper.markers import project_markers, reformat_span, reformat_spans, strip_markdown_inline


@pytest.mark.unit
@pytest.mark.subsys_map
def test_projection_round_trips_the_formatted_line() -> None:
    md = "Run **`uv run poe qa_fast`** before *every* commit; never touch `CLAUDE.md` by hand."
    plain = strip_markdown_inline(md)
    assert reformat_spans(md, plain, [plain]) == [md]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_each_span_gets_only_its_own_markers() -> None:
    md = "The operator decides. Run `uv run poe qa_fast` before **every** commit."
    plain = strip_markdown_inline(md)
    first, second = reformat_spans(md, plain, ["The operator decides.", "Run uv run poe qa_fast before every commit."])
    assert first == "The operator decides."
    assert second == "Run `uv run poe qa_fast` before **every** commit."


@pytest.mark.unit
@pytest.mark.subsys_map
def test_repeated_and_overlapping_tokens_locate_in_document_order() -> None:
    # `ab` then `b`: the cursor must move past the whole first run, not one char in,
    # or `b` would be found inside `ab`. Repeated `x` runs land on successive copies.
    assert project_markers("`ab` `b`", "ab b") == [(0, 2, "`"), (3, 4, "`")]
    assert project_markers("`x` and `x`", "x and x") == [(0, 1, "`"), (6, 7, "`")]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_nested_code_inside_bold_projects_both_without_doubling() -> None:
    md = "keep **secrets** out of **`CLAUDE.md`**"
    plain = strip_markdown_inline(md)
    assert reformat_spans(md, plain, [plain]) == [md]
    assert project_markers(md, plain) == [(5, 12, "**"), (20, 29, "**"), (20, 29, "`")]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_marker_straddling_a_span_boundary_is_clipped_to_each_side() -> None:
    markers = [(4, 11, "`")]  # `foo bar` spanning two spans "Run foo" | "bar now"
    assert reformat_span("Run foo", 0, markers) == "Run `foo`"
    assert reformat_span("bar now", 8, markers) == "`bar` now"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_unlocatable_run_and_unfound_span_pass_through() -> None:
    # A run whose content the AST reshaped is skipped; a span not in the plain text is returned as is.
    assert project_markers("see `gone`", "see elsewhere") == []
    assert reformat_spans("see `x`", "see x", ["not here"]) == ["not here"]


# ── red-first regressions ────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_code_span_content_with_underscores_round_trips_verbatim() -> None:
    # `__init__.py` inside backticks must not be read as bold/emphasis markers.
    md = "Never edit `__init__.py` or `__all__` by hand."
    plain = strip_markdown_inline(md)
    assert plain == "Never edit __init__.py or __all__ by hand."
    assert project_markers(md, plain) == [(11, 22, "`"), (26, 33, "`")]
    assert reformat_spans(md, plain, [plain]) == [md]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_earlier_bare_mention_does_not_steal_a_later_code_span() -> None:
    md = "Install uv first. Then run `uv` sync."
    plain = strip_markdown_inline(md)
    assert project_markers(md, plain) == [(27, 29, "`")]
    assert reformat_spans(md, plain, ["Install uv first.", "Then run uv sync."]) == [
        "Install uv first.",
        "Then run `uv` sync.",
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_emphasis_around_a_snake_case_identifier_is_projected() -> None:
    md = "Always run *qa_fast* first, then _every_ check."
    plain = strip_markdown_inline(md)
    assert plain == "Always run qa_fast first, then every check."
    assert reformat_spans(md, plain, [plain]) == [md]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_glob_star_inside_bold_does_not_pair_as_emphasis() -> None:
    md = "Prefer **notes-*.md** files."
    plain = strip_markdown_inline(md)
    assert plain == "Prefer notes-*.md files."
    assert project_markers(md, plain) == [(7, 17, "**")]
    assert reformat_spans(md, plain, [plain]) == [md]


# ── triple-star bold+italic must both project ───────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_triple_star_bold_italic_projects_as_italic_around_bold() -> None:
    """The parse reads `***x***` as an italic run around a bold run over the same words."""
    md = "A ***bold italic*** run."
    plain = "A bold italic run."
    assert project_markers(md, plain) == [(2, 13, "*"), (2, 13, "**")]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_triple_star_bold_italic_round_trips() -> None:
    md = "A ***bold italic*** run."
    plain = strip_markdown_inline(md)
    assert plain == "A bold italic run."
    assert reformat_spans(md, plain, [plain]) == [md]


def _inline_parses_for_nest(depth: int, monkeypatch: pytest.MonkeyPatch) -> tuple[int, list[tuple[int, int, str]]]:
    """How many inline parses projecting a `depth`-deep nest of italic runs takes, and the projection."""
    md = "Never " + "*a " * depth + "b" + " a*" * depth
    plain = strip_markdown_inline(md)
    md_parser._inline_spans.cache_clear()
    parses = 0
    real = md_parser.md_parser.parseInline

    def counting(*args: Any, **kwargs: Any) -> Any:
        nonlocal parses
        parses += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(md_parser.md_parser, "parseInline", counting)
    markers = project_markers(md, plain)
    monkeypatch.undo()
    return parses, markers


@pytest.mark.unit
@pytest.mark.subsys_map
def test_deep_nest_of_runs_is_parsed_a_bounded_number_of_times(monkeypatch: pytest.MonkeyPatch) -> None:
    """Doubling the nest depth adds no inline parses: a long run's content is cut from one parse."""
    small, small_markers = _inline_parses_for_nest(400, monkeypatch)
    large, large_markers = _inline_parses_for_nest(800, monkeypatch)
    assert large <= small + 2
    assert len(small_markers) == 400
    assert len(large_markers) == 800
