"""Preservation on the real mapper: a rewrite that ties a rule about a whole class to one named
construct is reported as narrowed, a sentence split that leaves a fragment behind is reported as
dangling, and a construct added to a rule without narrowing it is listed."""

from __future__ import annotations

import pytest

from tests.unit.test_preservation import _compare_edit

_HUB_1 = "Plan the change, then act on sensible defaults and present finished work; do not re-ask at every gate."
_HUB_2 = "Once a direction is approved, carry it to completion. Collapse multi-step approvals into one."


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before", "after"),
    [
        (_HUB_1, _HUB_1.replace("every gate", "every `AskUserQuestion` gate")),
        (_HUB_2, _HUB_2.replace("into one.", "into one `AskUserQuestion` call.")),
        ("Ask before deleting any file.", "Ask before deleting any `.env` file."),
        ("Ask before deleting any file.", "Ask before deleting any `.env`."),
    ],
)
def test_a_construct_inserted_after_a_general_quantifier_narrows_the_rule(tmp_path, before, after) -> None:
    ground = "\n\nThe `AskUserQuestion` tool and `.env` files exist.\n"
    result = _compare_edit(tmp_path, before + ground, after + ground)
    assert result["narrowed_instructions"]
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_sibling_sentence_naming_the_construct_does_not_excuse_the_insertion(tmp_path) -> None:
    before = "Merge small commits into one. Reserve `squash` for long branches."
    after = "Merge small commits into one `squash` commit. Reserve `squash` for long branches."
    result = _compare_edit(tmp_path, before, after)
    assert result["narrowed_instructions"]
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_construct_the_same_sentence_already_names_after_the_quantifier_does_not_narrow(tmp_path) -> None:
    before = "Ask before deleting any `.env` file."
    after = "Always ask before deleting any `.env` file."
    result = _compare_edit(tmp_path, before, after)
    assert result["narrowed_instructions"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    "before, after",
    [
        ("Run the linter before you commit.", "Run the `ruff` linter before you commit."),
        ("Run the tests.", "Run the tests with `pytest`."),
        ("Run the linter.", "Run `ruff`."),
    ],
)
def test_a_construct_added_without_a_quantifier_does_not_narrow(tmp_path, before, after) -> None:
    ground = "\n\nThe `ruff` and `pytest` tools exist.\n"
    result = _compare_edit(tmp_path, before + ground, after + ground)
    assert result["narrowed_instructions"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_construct_added_to_a_kept_rule_is_listed_not_failed(tmp_path) -> None:
    ground = "\n\nThe `pytest` tool exists.\n"
    result = _compare_edit(tmp_path, "Run the tests." + ground, "Run the tests with `pytest`." + ground)
    assert [e["line"] for e in result["made_specific"]] == [1]
    assert result["made_specific"][0]["after"] == "Run the tests with `pytest`."
    assert result["ok"] is True


_LINK = (
    "- [Release process](release_process.md) — the maintainers designed this release process; "
    "treat the process as deliberate intent — "
)
_ROLE = (
    "You are a release author: you read the request, classify the change into one of the "
    "four change types (per `docs/changes.md`), and write or update the matching "
    "entry at its canonical path."
)
_ORIENT = (
    "Load targeted orientation: read the overview at `docs/index.md` as the base, read exactly "
    "the artifacts the invocation names, load a live recent-work seed, and synthesize the set "
    "into one snapshot."
)


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before", "after"),
    [
        (_LINK + "ask, don't refactor.", _LINK + "ask. *Don't refactor the process.*"),
        (
            _ROLE,
            "You are a release author: you read the request.\n\n"
            "Classify the change into one of the four change types (per `docs/changes.md`).\n\n"
            "Write or update the matching entry at its canonical path.",
        ),
        (
            _ROLE,
            "You are a release author who reads the request.\n\n"
            "Classify the change into one of the four change types (per `docs/changes.md`).\n\n"
            "Write or update the matching entry at its canonical path.",
        ),
        (
            _ORIENT,
            "Load targeted orientation by reading the overview at `docs/index.md` as the base.\n\n"
            "Read exactly the artifacts the invocation names.\n\n"
            "Load a live recent-work seed.\n\n"
            "Synthesize the set into one snapshot.",
        ),
    ],
)
def test_a_split_that_leaves_a_fragment_behind_is_dangling(tmp_path, before, after) -> None:
    result = _compare_edit(tmp_path, before + "\n", after + "\n")
    assert result["dangling_fragments"]
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before", "after"),
    [
        (_LINK + "ask, don't refactor.", _LINK + "ask about the process; don't refactor it."),
        (
            _LINK + "ask, don't refactor.",
            _LINK.rstrip("— ").rstrip() + ". Ask about the architecture; don't refactor it.",
        ),
        (
            _ROLE,
            "You are a release author.\n\nRead the request.\n\n"
            "Classify the change into one of the four change types (per `docs/changes.md`).\n\n"
            "Write or update the matching entry at its canonical path.",
        ),
        (
            _ORIENT,
            "Load targeted orientation.\n\nRead the overview at `docs/index.md` as the base.\n\n"
            "Read exactly the artifacts the invocation names.\n\nLoad a live recent-work seed.\n\n"
            "Synthesize the set into one snapshot.",
        ),
        (
            _ROLE,
            "You are a release author who reads the request.\n\n"
            "You are a release author who classifies the change into one of the four change types "
            "(per `docs/changes.md`).\n\n"
            "You are a release author who writes or updates the matching entry at its canonical path.",
        ),
        ("Run the tests, then commit the result.", "Run the tests. Then commit the result."),
        (
            "Before you push: run the tests, run the linter.",
            "Before you push: run the tests. Before you push: run the linter.",
        ),
        ("Use `uv run` for Python; never call bare `python3`.", "Use `uv run` for Python. Never call bare `python3`."),
    ],
)
def test_a_clean_split_leaves_no_dangling_fragment(tmp_path, before, after) -> None:
    result = _compare_edit(tmp_path, before + "\n", after + "\n")
    assert result["dangling_fragments"] == []


_UNRELATED = "\n\nRun the tests before you push.\n"


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    "sentence",
    [
        _LINK + "ask, don't refactor.",
        "Convert each requested question to a position or an `choice: pick` tag, "
        "and name the conversion in the return; keep the original wording of the question in the log.",
        "Load `docs:roles/x/voice` before composing any external-facing copy (launch post, landing copy, "
        "release note), and add `docs:roles/x/structure` for long-form.",
    ],
)
def test_an_unchanged_long_sentence_is_never_a_dangling_fragment(tmp_path, sentence) -> None:
    result = _compare_edit(tmp_path, sentence + _UNRELATED, sentence + "\n\nRun the tests before every push.\n")
    assert result["dangling_fragments"] == []
