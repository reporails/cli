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
_SERIES_HEAD = (
    "Re-derive any budget-claim from the owning team's measured evidence (`docs/results.md`), "
    "seed that evidence into a review before opinions form"
)
_SERIES = _SERIES_HEAD + ", and read a misfiring detector as a broken instrument to fix."
_SERIES_CUT = _SERIES_HEAD + ". Read a misfiring detector as a broken instrument to fix."
_SEMI = _SERIES_HEAD.replace("), seed", "), and seed") + "; read a misfiring detector as a broken instrument to fix."
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
        (
            _ROLE,
            "You are a release author: you read the request, classify the change into one of the "
            "four change types (per `docs/changes.md`).\n\n"
            "You write or update the matching entry at its canonical path.",
        ),
        (_SERIES, _SERIES_CUT),
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
            "Select the artifacts for the task \u2014 rank candidates by term overlap, pick the best match "
            "(at most one or two per class), name each chosen artifact and why, then load them per the procedure.",
            "Select the artifacts for the task \u2014 rank candidates by term overlap, pick the best match "
            "(at most one or two per class), name each chosen artifact and why.\n\n"
            "Then load them per the procedure.",
        ),
        (
            "Rank candidates by term overlap, pick the best match (at most one or two per class), name each "
            "chosen artifact and why, then load them per the procedure.",
            "Rank candidates by term overlap, pick the best match (at most one or two per class), name each "
            "chosen artifact and why.\n\nThen load them per the procedure.",
        ),
        (
            _SERIES,
            "Re-derive any budget-claim from the owning team's measured evidence (`docs/results.md`).\n\n"
            "Seed that evidence into a review before opinions form.\n\n"
            "Read a misfiring detector as a broken instrument to fix.",
        ),
        (_SEMI, _SEMI.replace("; read", ". Read")),
        (
            _ROLE,
            "You are a release author: you read the request and classify the change into one of the "
            "four change types (per `docs/changes.md`).\n\n"
            "You write or update the matching entry at its canonical path.",
        ),
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


_SPEC = (
    "Produce the spec and define WHAT to build; the engineers own HOW within their team, "
    "and the manager files the spec."
)


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before", "after"),
    [
        (
            _SPEC,
            _SPEC.replace(
                "Produce the spec and define WHAT to build;",
                "Produce the product spec. Define WHAT to build in that spec;",
            ),
        ),
        ("Review the report and send the summary.", "Review the report. Send the summary in that report."),
    ],
)
def test_a_place_built_from_a_word_the_sentence_used_as_an_object_narrows_the_rule(tmp_path, before, after) -> None:
    result = _compare_edit(tmp_path, before + "\n", after + "\n")
    assert result["narrowed_instructions"]
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("Write files to the scratch dir.", "Write files in the scratch dir."),
        ("Run the tests in CI before you push.", "In CI, run the tests before you push."),
    ],
)
def test_a_place_the_sentence_already_stood_in_a_phrase_does_not_narrow(tmp_path, before, after) -> None:
    result = _compare_edit(tmp_path, before + "\n", after + "\n")
    assert result["narrowed_instructions"] == []


_NEIGHBOUR = (
    "Own the product spec content: feature shape, scope, priorities. "
    "Produce the spec and define WHAT to build; the architects own HOW within their team, "
    "and the manager files the spec into the tracker. Stamp the standard header as a norm of the craft."
)


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_place_built_from_a_word_a_neighbour_sentence_used_as_an_object_narrows_the_rule(tmp_path) -> None:
    after = _NEIGHBOUR.replace(
        "Produce the spec and define WHAT to build;", "Produce the product spec. Define WHAT to build in that spec;"
    )
    result = _compare_edit(tmp_path, _NEIGHBOUR + "\n", after + "\n")
    assert result["narrowed_instructions"]
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    "sentence",
    [
        "*Load the live seed on every non-`help` invocation \u2014 anchor the synthesis to current state,* "
        "*never return a stale snapshot of old data.*",
        "`tool check` emits human-readable findings on `stdout` and exits non-zero on any error finding.",
    ],
)
def test_an_unchanged_sentence_is_never_narrowed(tmp_path, sentence) -> None:
    result = _compare_edit(tmp_path, sentence + _UNRELATED, sentence + "\n\nRun the tests before every push.\n")
    assert result["narrowed_instructions"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before", "after"),
    [
        (
            "Check the bar's sparsity non-examples against the dry-run.",
            "Check the bar's sparsity non-examples in `docs/roles/<role>/` against the dry-run.",
        ),
        (
            "Load `voice.md` before composing, then match every external copy to the style guide.",
            "Load the style guide at `voice.md` before composing, then match every external copy to the style guide.",
        ),
        (
            "Hold the team's north star and drive the roadmap toward it: ask first.",
            "Hold the team's north star at `vision.md` and drive the roadmap toward it: ask first.",
        ),
    ],
)
def test_a_place_that_opens_with_a_named_construct_is_listed_not_narrowed(tmp_path, before, after) -> None:
    ground = "\n\nThe `docs/roles/<role>/`, `voice.md` and `product-vision` files exist.\n"
    result = _compare_edit(tmp_path, before + ground, after + ground)
    assert result["narrowed_instructions"] == []


_CODE_SPLITS = [
    (
        "Convert each requested question to a position or an `choice: <question> \u2014 <why>` tag, "
        "and name the conversion in the return; keep the original wording of the question in the log.",
        "Convert each requested question to a position or an `choice: <question> \u2014 <why>` tag."
        "\n\nName the conversion in the return.\n\nKeep the original wording of the question in the log.",
    ),
    (
        "Load `docs:guides/voice` before composing any external-facing copy (launch post, landing copy), "
        "and add `x/structure` for long-form.",
        "Load `docs:guides/voice` before composing any external-facing copy (launch post, landing copy)."
        "\n\nAdd `x/structure` for long-form.",
    ),
    (
        "Group tickets by tagging a `milestone:` label on the ticket; the board view "
        "shows the grouping (see ticket 9), so do not add a separate grouping field.",
        "Group tickets by tagging a `milestone:` label on the ticket; the board view "
        "shows the grouping (see ticket 9).\n\nDo not add a separate grouping field.",
    ),
    (
        "**`/search <query>`** \u2014 resolve a freeform description (e.g. `how do we find a page?`) to the "
        "best-matching pages, then load the matched pages (the stretch form; see `## Query matching`).",
        "**`/search <query>`** \u2014 resolve a freeform description (e.g. `how do we find a page?`) to the "
        "best-matching pages.\n\nThen load the matched pages (the stretch form; see `## Query matching`).",
    ),
]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(("before", "after"), _CODE_SPLITS)
def test_a_colon_in_code_or_a_then_step_is_not_a_dangling_fragment(tmp_path, before, after) -> None:
    result = _compare_edit(tmp_path, before + "\n", after + "\n")
    assert result["dangling_fragments"] == []
