"""A line that introduces a list, a code block or a table rides the wire marked as a lead-in.

Real markdown goes through the real mapper (parse, instruction cut, charge classifier, list fold) and
the projection: the mark is read from the markdown's structure, so it holds for list items too short
to be atoms of their own, and it lands on the last piece a line is cut into.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper.bio_tagger import multislot_available

requires_charge_model = pytest.mark.skipif(not multislot_available(), reason="Bundled multi-slot graphs not available")


def _wire(tmp_path: Path, markdown: str) -> list[tuple[int, bool]]:
    """(line, carries `li`) for each atom the file sends."""
    from reporails_cli.core.mapper.models import get_models
    from reporails_cli.core.mapper.pipeline import map_ruleset
    from reporails_cli.core.platform.adapters.payload import project_payload

    f = tmp_path / "CLAUDE.md"
    f.write_text(markdown)
    ruleset = map_ruleset([f], models=get_models(), root=tmp_path, cache_dir=None)
    return [(a["line"], bool(a.get("li"))) for a in project_payload(ruleset, tmp_path)["atoms"]]


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_charge_model
@pytest.mark.parametrize(
    "markdown",
    [
        "Run these:\n\n- a\n- b\n",
        "Run these checks before you commit:\n\n- the unit tests\n- the linter\n",
        "Run these checks before you commit:\n\n1. the unit tests\n2. the linter\n",
        "Run this before you commit:\n\n```\nmake test\n```\n",
        "Run this before you commit:\n\n| Step | Command |\n| --- | --- |\n| test | make test |\n",
    ],
)
def test_a_colon_line_above_a_list_a_code_block_or_a_table_rides_the_wire_as_a_lead_in(
    tmp_path: Path, markdown: str
) -> None:
    assert _wire(tmp_path, markdown)[0] == (1, True)


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_charge_model
@pytest.mark.parametrize(
    "markdown",
    [
        "Run these checks before you commit:\n\nAlways run the linter.\n",
        "Run these checks before you commit\n\n- the unit tests\n- the linter\n",
        "Run these checks before you commit.\n\n- the unit tests\n- the linter\n",
    ],
)
def test_a_line_without_a_colon_or_without_a_block_after_it_is_no_lead_in(tmp_path: Path, markdown: str) -> None:
    assert not any(li for _, li in _wire(tmp_path, markdown))


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_charge_model
def test_a_line_cut_into_pieces_marks_only_its_last_piece(tmp_path: Path) -> None:
    markdown = "Read the docs first. Never edit these files:\n\n- the lockfile\n- the generated schema\n"
    wire = _wire(tmp_path, markdown)
    on_line_one = [li for line, li in wire if line == 1]
    assert len(on_line_one) >= 2
    assert on_line_one == [False] * (len(on_line_one) - 1) + [True]


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_charge_model
def test_a_lead_in_whose_list_is_its_object_still_rides_the_wire_and_the_items_do_not(tmp_path: Path) -> None:
    wire = _wire(tmp_path, "Audit these files:\n\n- `CLAUDE.md`\n- `AGENTS.md`\n\nNever skip the version check.\n")
    assert wire[0] == (1, True)
    assert [line for line, _ in wire if line in (3, 4)] == []
