"""The preservation check on headings, through the real mapper: a heading that is itself an
instruction must survive a rewrite, and a bare negative heading is read the way the mapper reads
it, in any markdown style."""

from __future__ import annotations

import pytest

from reporails_cli.interfaces.mcp import remedy_brief
from tests.unit.test_preservation import _compare_edit
from tests.unit.test_remedy_brief import _main_location, requires_model, requires_rules

_NEVER = "# Service\n\n## Never Push Directly to Main\n\nOpen a pull request from a feature branch.\n"
_ALWAYS = "# Service\n\n## Always Run Tests Before Pushing\n\nOpen a pull request from a feature branch.\n"
_STEP = "# Skill\n\n### Step 2: Evaluate each check entry\n\nRead the entry and note what it needs.\n"
_TOPIC = "# Service\n\n## Deployment\n\nOpen a pull request from a feature branch.\n"
_DOUBLES = ("- Use mock objects in tests.\n", "- Use test doubles in the test suite.\n")
_NEGATED = ("- Do not use mock objects in tests.\n", "- Do not use test doubles in the test suite.\n")


def _doc(heading: str, items: tuple[str, ...]) -> str:
    return f"{heading}\n\n{''.join(items)}"


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_renamed_prohibition_heading_with_nothing_moved_into_the_body_is_not_ok(tmp_path) -> None:
    after = _NEVER.replace("Never Push Directly to Main", "Branching")
    result = _compare_edit(tmp_path, _NEVER, after)
    assert result["ok"] is False
    assert [e["text"] for e in result["lost_instructions"]] == ["Never Push Directly to Main"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_renamed_prohibition_heading_whose_body_gains_the_directive_is_not_ok(tmp_path) -> None:
    after = _NEVER.replace("Never Push Directly to Main", "Branching") + "\nPush directly to main.\n"
    result = _compare_edit(tmp_path, _NEVER, after)
    assert result["ok"] is False
    assert result["polarity_flips"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_renamed_prohibition_heading_whose_body_gains_the_prohibition_is_ok(tmp_path) -> None:
    after = _NEVER.replace("Never Push Directly to Main", "Branching") + "\nNever push directly to main.\n"
    result = _compare_edit(tmp_path, _NEVER, after)
    assert result["ok"] is True
    assert result["kept"]["instructions"] == 2


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_an_unchanged_prohibition_heading_is_ok(tmp_path) -> None:
    result = _compare_edit(tmp_path, _NEVER, _NEVER)
    assert result["ok"] is True
    assert result["lost_instructions"] == [] and result["added_instructions"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_renamed_directive_heading_with_nothing_moved_into_the_body_is_not_ok(tmp_path) -> None:
    after = _ALWAYS.replace("Always Run Tests Before Pushing", "Pushing")
    result = _compare_edit(tmp_path, _ALWAYS, after)
    assert result["ok"] is False
    assert [e["text"] for e in result["lost_instructions"]] == ["Always Run Tests Before Pushing"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_renamed_directive_heading_whose_body_gains_the_directive_is_ok(tmp_path) -> None:
    after = _ALWAYS.replace("Always Run Tests Before Pushing", "Pushing") + "\nAlways run tests before pushing.\n"
    assert _compare_edit(tmp_path, _ALWAYS, after)["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_an_unchanged_directive_heading_is_ok(tmp_path) -> None:
    assert _compare_edit(tmp_path, _ALWAYS, _ALWAYS)["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_an_unchanged_procedure_step_title_is_ok(tmp_path) -> None:
    result = _compare_edit(tmp_path, _STEP, _STEP)
    assert result["ok"] is True
    assert result["lost_instructions"] == [] and result["added_instructions"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_renamed_topic_heading_stays_ok(tmp_path) -> None:
    assert _compare_edit(tmp_path, _TOPIC, _TOPIC.replace("Deployment", "Releases"))["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_setext_negative_heading_renamed_over_negated_items_is_not_ok(tmp_path) -> None:
    before = _doc("Don'ts\n------", _DOUBLES)
    result = _compare_edit(tmp_path, before, _doc("Test doubles\n------------", _NEGATED))
    assert result["ok"] is False
    assert result["relabelled_negative_headings"] == [{"line": 1, "text": "Don'ts"}]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_blockquoted_negative_heading_renamed_over_negated_items_is_not_ok(tmp_path) -> None:
    result = _compare_edit(tmp_path, _doc("> ## Never", _DOUBLES), _doc("> ## Doubles", _NEGATED))
    assert result["ok"] is False
    assert result["relabelled_negative_headings"] == [{"line": 1, "text": "> ## Never"}]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_negative_heading_restyled_as_setext_with_the_same_label_is_ok(tmp_path) -> None:
    result = _compare_edit(tmp_path, _doc("## Don'ts", _DOUBLES), _doc("Don'ts\n------", _DOUBLES))
    assert result["relabelled_negative_headings"] == []
    assert result["ok"] is True


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_closed_negative_heading_renamed_over_negated_items_is_not_ok(tmp_path) -> None:
    result = _compare_edit(tmp_path, _doc("## Forbidden ##", _DOUBLES), _doc("## Doubles ##", _NEGATED))
    assert result["ok"] is False
    assert result["relabelled_negative_headings"] == [{"line": 1, "text": "## Forbidden ##"}]


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_model
@requires_rules
def test_the_brief_marks_a_heading_that_is_an_instruction_with_its_polarity(tmp_path) -> None:
    (tmp_path / "CLAUDE.md").write_text(
        "# Service\n\n## Never Push Directly to Main\n\nOpen a pull request from a feature branch.\n"
        "\n## Deployment\n\nRelease from the main branch.\n",
        encoding="utf-8",
    )
    reply = remedy_brief.remedy_brief_tool(_main_location(["CLAUDE.md"]), tmp_path)
    (entry,) = reply["files"]
    headings = {h["text"]: h for h in entry["headings"]}
    assert headings["Never Push Directly to Main"]["polarity"] == -1
    assert "polarity" not in headings["Deployment"]
    assert "polarity" not in headings["Service"]
    assert all(e["text"] not in headings for e in entry["instructions"])
