"""How a markdown table is broken into units and scored.

A table creates no units of its own. A row is one LINE, the pipe is a mid-line
delimiter, and the ordinary line rules decide the rest: sentence edges cut, cell
edges do not, and every row — header included — is read rather than skipped.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.parse import tokenize


def _rows(md: str) -> list:
    return [a for a in tokenize(md, "structure-aware") if a.format == "table"]


_TABLE = """| Rule | Requirement |
|---|---|
| `ails check` | Always run it before commit. Do not skip it. |
| Emoji ban | Never use **emoji** in a heading |
"""


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_row_is_one_line_with_its_cells_joined() -> None:
    md = "| Rebuild | Always run the generator before commit |\n|---|---|\n| a | b |\n"
    assert _rows(md)[0].text == "Rebuild | Always run the generator before commit"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_cell_edge_does_not_split_one_instruction() -> None:
    # The label and the instruction sit in different cells; they stay one unit.
    rows = _rows(_TABLE)
    assert "Emoji ban | Never use **emoji** in a heading" in [r.text for r in rows]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_sentence_edge_inside_a_row_does_split() -> None:
    texts = [r.text for r in _rows(_TABLE)]
    assert "`ails check` | Always run it before commit." in texts
    assert "Do not skip it." in texts


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_row_is_classified_rather_than_forced_neutral() -> None:
    by_text = {r.text: r for r in _rows(_TABLE)}
    assert by_text["Do not skip it."].charge == "CONSTRAINT"
    assert by_text["`ails check` | Always run it before commit."].charge == "DIRECTIVE"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_command_led_row_is_not_written_off_as_a_reference() -> None:
    # The same shape in a paragraph reads as a pointer; inside a real table it
    # is simply how every command-led rule row looks. (A header row only labels
    # its columns, so the instruction sits in a body row.)
    md = "| Command | Rule |\n|---|---|\n| `ails check` | Do not bypass it |\n"
    row = _rows(md)[1]
    assert row.rule != "structural"
    assert row.charge == "CONSTRAINT"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_header_row_is_read_not_skipped() -> None:
    header = _rows(_TABLE)[0]
    assert header.text == "Rule | Requirement"
    assert header.charge == "NEUTRAL"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_row_carries_a_marker_free_parallel_form() -> None:
    row = next(r for r in _rows(_TABLE) if r.text.startswith("Emoji ban"))
    assert row.plain_text == "Emoji ban | Never use emoji in a heading"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_decoration_is_removed_from_a_cell() -> None:
    md = "| Step | 🚀 Ship it |\n|---|---|\n| a | b |\n"
    assert _rows(md)[0].text == "Step | Ship it"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_placeholder_row_survives_nothing() -> None:
    # `A. | … | …` is a template skeleton: a list marker and three ellipses.
    md = "| Option | Notes |\n|---|---|\n| A. | … |\n| B. | … |\n"
    assert [r.text for r in _rows(md)] == ["Option | Notes"]
