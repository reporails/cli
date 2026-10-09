"""Preservation on the real mapper: a rewrite that ties a rule about a whole class to one named
construct is reported as narrowed, a sentence split that leaves a fragment behind is reported as
dangling, and a construct added to a rule without narrowing it is listed."""

from __future__ import annotations

import pytest

from tests.unit.test_preservation import _compare_edit

_PLAN_1 = "Plan the change, then act on sensible defaults and present finished work; do not re-ask at every gate."
_PLAN_2 = "Once a direction is approved, carry it to completion. Collapse multi-step approvals into one."


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before", "after"),
    [
        (_PLAN_1, _PLAN_1.replace("every gate", "every `AskUserQuestion` gate")),
        (_PLAN_2, _PLAN_2.replace("into one.", "into one `AskUserQuestion` call.")),
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
    "Lint every changed file with the shared config (`docs/lint.md`), "
    "cache the results between builds until the next deploy"
)
_SERIES = _SERIES_HEAD + ", and report a failing check as a blocked release."
_SERIES_CUT = _SERIES_HEAD + ". Report a failing check as a blocked release."
_SEMI = _SERIES_HEAD.replace("), cache", "), and cache") + "; report a failing check as a blocked release."
_RELEASER = (
    "You are the release manager: you check the build status, sort the failures into one of "
    "three buckets (per `docs/triage.md`), and file or update the matching ticket in the tracker."
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
        (
            _RELEASER,
            "You are the release manager: you check the build status, sort the failures into one of "
            "three buckets (per `docs/triage.md`).\n\nYou file or update the matching ticket in the tracker.",
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
        (
            "Prepare the release \u2014 collect the changed files, sort them by owner "
            "(at most one or two per team), name each file and why, then publish the notes per the template.",
            "Prepare the release \u2014 collect the changed files, sort them by owner "
            "(at most one or two per team), name each file and why.\n\n"
            "Then publish the notes per the template.",
        ),
        (
            "Collect the changed files, sort them by owner (at most one or two per team), name each "
            "file and why, then publish the notes per the template.",
            "Collect the changed files, sort them by owner (at most one or two per team), name each "
            "file and why.\n\nThen publish the notes per the template.",
        ),
        (
            _SERIES,
            "Lint every changed file with the shared config (`docs/lint.md`).\n\n"
            "Cache the results between builds until the next deploy.\n\n"
            "Report a failing check as a blocked release.",
        ),
        (_SEMI, _SEMI.replace("; report", ". Report")),
        (
            _RELEASER,
            "You are the release manager: you check the build status and sort the failures into one of "
            "three buckets (per `docs/triage.md`).\n\nYou file or update the matching ticket in the tracker.",
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
    "Write the test plan and decide WHICH cases to run; the developers own HOW within their team, "
    "and the manager files the plan in the tracker."
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
                "Write the test plan and decide WHICH cases to run;",
                "Write the release test plan. Decide WHICH cases to run in that plan;",
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
    "Keep the test plan current: scope, owners, dates. "
    "Write the test plan and decide WHICH cases to run; the developers own HOW within their team, "
    "and the manager files the plan in the tracker. Add the standard header to each page."
)


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_place_built_from_a_word_a_neighbour_sentence_used_as_an_object_narrows_the_rule(tmp_path) -> None:
    after = _NEIGHBOUR.replace(
        "Write the test plan and decide WHICH cases to run;",
        "Write the release test plan. Decide WHICH cases to run in that plan;",
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
        "*Run the quick checks on every non-`draft` commit \u2014 keep the output short,* "
        "*never print a stale log of old runs.*",
        "`build check` emits readable results on `stdout` and exits non-zero on any failing job.",
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
            "Compare the build times of the slow jobs against the baseline.",
            "Compare the build times of the slow jobs in `ci/jobs/<name>/` against the baseline.",
        ),
        (
            "Open `setup.md` before installing, then match every config line to the template.",
            "Open the install notes at `setup.md` before installing, then match every config line to the template.",
        ),
        (
            "Update the changelog and tag each release from it: ask first.",
            "Update the changelog at `CHANGES.md` and tag each release from it: ask first.",
        ),
    ],
)
def test_a_place_that_opens_with_a_named_construct_is_listed_not_narrowed(tmp_path, before, after) -> None:
    ground = "\n\nThe `ci/jobs/<name>/`, `setup.md` and `CHANGES.md` files exist.\n"
    result = _compare_edit(tmp_path, before + ground, after + ground)
    assert result["narrowed_instructions"] == []


_CODE_SPLITS = [
    (
        "Write each failing step as a line or a `step: <name> \u2014 <reason>` entry, "
        "and put the summary at the end; keep the raw log in the artifact folder.",
        "Write each failing step as a line or a `step: <name> \u2014 <reason>` entry."
        "\n\nPut the summary at the end.\n\nKeep the raw log in the artifact folder.",
    ),
    (
        "Read `docs:guides/install` before changing any build script (shell scripts, makefiles), "
        "and add `docs:guides/cache` for slow builds.",
        "Read `docs:guides/install` before changing any build script (shell scripts, makefiles)."
        "\n\nAdd `docs:guides/cache` for slow builds.",
    ),
    (
        "Mark flaky tests by adding a `flaky:` tag to the test name; the nightly report lists "
        "every marked test (see ticket 9), so do not keep a separate list.",
        "Mark flaky tests by adding a `flaky:` tag to the test name; the nightly report lists "
        "every marked test (see ticket 9).\n\nDo not keep a separate list.",
    ),
    (
        "**`/deploy <env>`** \u2014 copy the build to the matching host (e.g. `which host is next?`), "
        "then restart the service (the last step; see `## Rollout`).",
        "**`/deploy <env>`** \u2014 copy the build to the matching host (e.g. `which host is next?`)."
        "\n\nThen restart the service (the last step; see `## Rollout`).",
    ),
    (
        "Read the plan, write the code, then run the tests, and commit the change.",
        "Read the plan, write the code.\n\nThen run the tests and commit the change.",
    ),
]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(("before", "after"), _CODE_SPLITS)
def test_a_colon_in_code_or_a_then_step_is_not_a_dangling_fragment(tmp_path, before, after) -> None:
    result = _compare_edit(tmp_path, before + "\n", after + "\n")
    assert result["dangling_fragments"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_real_colon_beside_a_code_span_with_the_same_text_still_opens_a_list(tmp_path) -> None:
    before = "Separate fields with `:`: name, type, and default."
    after = "Separate fields with `:`: name.\n\nType and default follow."
    result = _compare_edit(tmp_path, before + "\n", after + "\n")
    assert result["dangling_fragments"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_colon_in_code_after_a_prose_colon_still_opens_no_list(tmp_path) -> None:
    before = "Before you push: run the tests, run the linter, and join the keys with `:`."
    after = "Before you push: run the tests.\n\nRun the linter and join the keys with `:`."
    result = _compare_edit(tmp_path, before + "\n", after + "\n")
    assert result["dangling_fragments"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_new_place_word_after_a_named_construct_narrows_the_rule(tmp_path) -> None:
    ground = "\n\nThe `staging` host exists.\n"
    result = _compare_edit(
        tmp_path, "Run the migration." + ground, "Run the migration in `staging` environments." + ground
    )
    assert result["narrowed_instructions"]
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before", "after"),
    [
        (
            "When a brief asks for questions, convert each to a position or a `choice:` tag and name the "
            "conversion in the return.",
            "When a brief asks for questions, convert each question to a position or a `choice:` tag.\n\n"
            "When a brief asks for questions, name each question-to-position conversion in the dispatch return.",
        ),
        (
            "Write the design notes at `docs/design/*.md`, capture observations at `notes/<date>.md`, "
            "and return inline session output.",
            "Write the design notes at `docs/design/*.md`.\n\nCapture observations at `notes/<date>.md`.\n\n"
            "Return the rest of the UX output as inline session output.",
        ),
        ("Print the output.", "Print the rest of the output."),
        ("Fix the failing tests.", "Fix the remaining failing tests."),
    ],
)
def test_a_rest_or_remaining_cut_of_what_a_rule_covers_narrows_it(tmp_path, before, after) -> None:
    ground = "\n\nThe `choice:` tag, `docs/design/*.md` and `notes/<date>.md` exist.\n"
    result = _compare_edit(tmp_path, before + ground, after + ground)
    assert result["narrowed_instructions"]
    assert result["ok"] is False


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("Run the tests before you push.", "Always run the tests before you push."),
        ("Run the tests.", "Run the tests with `pytest`."),
        ("Run the linter.", "Run the `ruff` linter."),
        (
            "You read the request, classify it, and write the entry.",
            "You read the request. You classify it. You write the entry.",
        ),
        ("Before you push, run the tests.", "Run the tests before you push."),
        ("Call the API for each lookup.", "Call the REST API for each lookup."),
        ("Sleep between retries.", "Rest between retries."),
        ("Show the time left on the job.", "Show the remaining time on the job."),
    ],
)
def test_a_rewrite_that_adds_no_restricting_word_does_not_narrow(tmp_path, before, after) -> None:
    ground = "\n\nThe `pytest` and `ruff` tools exist.\n"
    result = _compare_edit(tmp_path, before + ground, after + ground)
    assert result["narrowed_instructions"] == []


_PUNCT_BEFORE = "Pass `--scope` (incl. `.`) to override the default. Run it with `make` and `lint`, then check `out`.\n"
_PUNCT_SPLIT = (
    "Pass `--scope` (incl. `.`) to override the default. Run it with `make`. Run it with `lint`. Then check `out`.\n"
)


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_sentence_split_does_not_repeat_a_punctuation_only_construct(tmp_path) -> None:
    result = _compare_edit(tmp_path, _PUNCT_BEFORE, _PUNCT_SPLIT)
    assert result["repeated_named"] == []
    assert result["lost_named"] == []
    assert result["invented_named"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_dropped_punctuation_only_construct_is_lost_and_an_added_one_is_invented(tmp_path) -> None:
    dropped = _compare_edit(tmp_path, _PUNCT_BEFORE, _PUNCT_SPLIT.replace(" (incl. `.`)", ""))
    assert dropped["lost_named"] == ["."]
    added = _compare_edit(
        tmp_path, "Join the keys with a plain :: between them.\n", "Join the keys with a plain `::` between them.\n"
    )
    assert [e["token"] for e in added["invented_named"]] == ["::"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_real_construct_mentioned_beyond_its_allowance_is_still_repeated(tmp_path) -> None:
    before = "Run `ruff` before you push.\n\nKeep the suite fast.\n"
    after = (
        "Run `ruff` before you push.\n\nKeep the suite fast.\n\nAlso always run `ruff` twice, since `ruff` matters.\n"
    )
    result = _compare_edit(tmp_path, before, after)
    assert [e["token"] for e in result["repeated_named"]] == ["`ruff`"]


_INTENT = (
    "- [Workflow vision since 2025-11](user_workflow_vision_since_2025_11.md) — the user dreamed/designed "
    "this build/release workflow since Nov 2025; "
    "treat the architecture as deliberate intent — ask, don't refactor.\n"
)


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_lead_in_sentence_with_every_item_as_its_own_sentence_is_no_fragment(tmp_path) -> None:
    after = _INTENT.replace(
        "deliberate intent — ask, don't refactor.",
        "deliberate intent. Ask the user about the architecture. *Do not refactor the architecture.*",
    )
    result = _compare_edit(tmp_path, _INTENT, after)
    assert result["dangling_fragments"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_lead_in_with_only_its_first_item_is_still_a_fragment(tmp_path) -> None:
    after = _INTENT.replace("deliberate intent — ask, don't refactor.", "deliberate intent — ask.")
    assert _compare_edit(tmp_path, _INTENT, after)["dangling_fragments"]


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_rephrased_lead_in_with_bare_imperatives_is_still_a_fragment(tmp_path) -> None:
    before = "You are the intake agent: you read the intent, classify it, and write the entry.\n"
    after = "You are the intake agent: you read the intent.\n\nClassify it.\n\nWrite the entry.\n"
    assert _compare_edit(tmp_path, before, after)["dangling_fragments"]


_PO_BEFORE = (
    "- Hand release-notes and build-work to the `reviewer` for cross-team filing at `work/<team>/`; "
    "routing through one owner keeps the build queue coherent. "
    "*Do not file plans directly into another team's surfaces, bypassing the `reviewer`.*"
)
_UX_BEFORE = (
    "- Frame each UX recommendation as one rationale-led `proposal` naming the interaction-shape alternative "
    "it sacrifices, keeping the user the decider. "
    "*Do not present a menu of N options absent genuine `AskUserQuestion` equipoise.*"
)


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("before", "after"),
    [
        (_PO_BEFORE, _PO_BEFORE.replace("file plans", "file release-notes or build-work plans")),
        (_UX_BEFORE, _UX_BEFORE.replace("present a menu", "present a UX recommendation as a menu")),
    ],
)
def test_a_qualifier_on_a_general_noun_narrows_even_when_the_line_uses_its_words(tmp_path, before, after) -> None:
    ground = "\n\nThe `reviewer` and `AskUserQuestion` exist.\n"
    result = _compare_edit(tmp_path, before + ground, after + ground)
    assert result["narrowed_instructions"]
    assert result["ok"] is False


_THEN_BEFORE = (
    "*Do not silently skip an entry that fails to load \u2014 name the missing key and the paths tried, "
    "then ask the maintainer; do not add a fallback path \u2014 the loader is strict.*\n"
)


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_sentence_that_starts_with_then_is_a_fragment_of_the_sentence_it_continued() -> None:
    from reporails_cli.core.heal.preservation.fragments import rewrite_cut

    before = _THEN_BEFORE.strip()
    cut = before.replace("tried, then", "tried.* *Then").replace("maintainer;", "maintainer.*").replace("; do", " do")
    assert rewrite_cut(before, cut.replace("maintainer.* do", "maintainer.* *Do")) == "step"
    assert rewrite_cut("Run the tests, then fix every failure.", "Run the tests. Then fix every failure.") == "step"


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_then_sentence_the_author_already_wrote_alone_is_no_fragment() -> None:
    from reporails_cli.core.heal.preservation.fragments import rewrite_cut

    same = "Run the tests. Then fix every failure."
    assert rewrite_cut(same, same) == ""
    assert rewrite_cut(same, "Run the tests.  Then fix every failure.") == ""


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_rewrite_that_cuts_a_then_step_into_its_own_sentence_is_reported(tmp_path) -> None:
    before = "Run the tests, then fix every failure.\n"
    result = _compare_edit(tmp_path, before, "Run the tests. Then fix every failure.\n")
    assert result["dangling_fragments"]
    unchanged = "Run the tests. Then fix every failure.\n"
    assert _compare_edit(tmp_path, unchanged, unchanged)["dangling_fragments"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_an_unchanged_then_clause_is_kept_when_another_line_changes(tmp_path) -> None:
    before = "Run the tests, then fix every failure.\n\nNever push to main.\n"
    after = "Run the tests, then fix every failure.\n\nDo not push to main.\n"
    assert _compare_edit(tmp_path, before, after)["dangling_fragments"] == []


@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.requires_model
def test_a_then_sentence_the_author_wrote_alone_is_kept_beside_the_same_step_in_a_clause(tmp_path) -> None:
    before = "Build the image, then commit.\n\nStage the files. Then commit.\n\nNever push to main.\n"
    after = before.replace("Never push", "Do not push")
    assert _compare_edit(tmp_path, before, after)["dangling_fragments"] == []
    assert rewrite_cut_of("Build the image, then commit. Stage the files. Then commit.") == ""


def rewrite_cut_of(line: str) -> str:
    from reporails_cli.core.heal.preservation.fragments import rewrite_cut

    return rewrite_cut(line, line)


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize(
    "after",
    [
        "Run the tests. Then, fix every failure.",
        "Run the tests. And then fix every failure.",
    ],
)
def test_a_then_step_with_a_comma_or_and_is_still_a_step(after: str) -> None:
    from reporails_cli.core.heal.preservation.fragments import rewrite_cut

    assert rewrite_cut("Run the tests, and then fix every failure.", after) == "step"
    assert rewrite_cut("Run the tests, then fix every failure.", after) == "step"
