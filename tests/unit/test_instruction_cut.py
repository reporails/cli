"""A sentence giving several instructions maps to one instruction each."""

from __future__ import annotations

import pytest

from reporails_cli.core.lint.client_checks import run_client_checks
from reporails_cli.core.mapper import bio_pipeline
from reporails_cli.core.mapper.instructions import instruction_count, instruction_texts
from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap, RulesetSummary

_needs_model = pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")


def _pieces(sentence: str) -> list[str]:
    return instruction_texts(sentence)


def _mapped(md: str) -> list[Atom]:
    atoms = bio_pipeline.apply_multislot(list(tokenize(md)))
    for a in atoms:
        a.file_path = "test.md"
    return [a for a in atoms if a.kind != "heading"]


def _charged(atoms: list[Atom]) -> list[str]:
    return [a.text for a in atoms if a.charge_value != 0]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "text",
    [
        "Validate the input and sanitize the output.",
        "Do not mock the database; exercise the real ProductCache in the test, and give every assert "
        "statement a message.",
        "Use `ruff` for linting, run `pytest` before committing, and never push to `main`.",
        "Read the file, then edit it.",
        "Build the image, then test it.",
        "*Do not edit generated files; do not commit secrets.*",
        "- Run `uv run poe qa_fast` and commit with `git commit --only`.",
        "Run the tests, then commit.",
        "Make sure the tests pass, then push the branch.",
        "Use `uv` to install packages; never edit the lockfile by hand.",
        "Use `uv` to install packages, never use pip, run the tests.",
        "Do not push to main, open a branch or a fork instead.",
        "Update README.md, CHANGELOG.md, and push the tag.",
        "Run the tests, lint, and commit the changes.",
    ],
)
def test_a_sentence_giving_two_instructions_is_counted_as_two(text: str) -> None:
    assert instruction_count(text) >= 2


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "text",
    [
        "Run the linter and the formatter.",
        "Run tests before committing and after merging.",
        "Write clean, readable, well-tested code.",
        "Use ruff for lint, format and type checks.",
        "`make build` — Build the service",
        "If the tests fail, fix them before you merge.",
        "Use `pytest` with `@pytest.mark.parametrize` for every boundary case.",
        "Flag when instructions try to do things they cannot (control retrieval, trigger cards, etc.).",
        "Note: pandoc is usually at `%LOCALAPPDATA%` — resolve it via `where pandoc`.",
        "**Rule:** run the checks before committing.",
        "Run `make build; make test` before merging.",
        "Run `make build, make test` before merging.",
        "Use tools such as grep, find and sed.",
        "Use git and make for builds.",
        "Use pytest and mock for tests.",
        "Use `uv` to install packages, add dependencies, and run scripts.",
        "Use a script to build, test, and deploy the service.",
        "Do not commit secrets, push credentials, or share tokens.",
        "Never commit secrets, push credentials or share tokens.",
        "Do not edit, rename, or delete generated files.",
        "Preserve `id`, `slug`, and coordinate fields in all rule frontmatter.",
        "Audit a rule's `checks.yml` for type correctness, gate efficiency, pattern quality, and match scope.",
        "Audit the rule for correctness, pattern quality and match scope.",
        "See the build and deploy guide.",
    ],
)
def test_a_sentence_giving_one_instruction_is_counted_as_one(text: str) -> None:
    assert instruction_count(text) <= 1


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("sentence", "pieces"),
    [
        ("Validate the input and sanitize the output.", ["Validate the input", "and sanitize the output."]),
        (
            "Do not mock the database; exercise the real cache in the test, and give every assert a message.",
            ["Do not mock the database;", "exercise the real cache in the test,", "and give every assert a message."],
        ),
        ("Before merging, run the tests, then commit.", ["Before merging, run the tests,", "then commit."]),
        ("Read the file — do not skim it.", ["Read the file —", "do not skim it."]),
        (
            "Use `uv` to install packages, add dependencies, and run scripts.",
            ["Use `uv` to install packages, add dependencies, and run scripts."],
        ),
        ("Run `make build, make test` before merging.", ["Run `make build, make test` before merging."]),
        ("Run the tests; if they fail, fix them.", ["Run the tests;", "if they fail, fix them."]),
        (
            "Do not edit the lockfile; when the build fails, run it again and read the log.",
            ["Do not edit the lockfile;", "when the build fails, run it again", "and read the log."],
        ),
        (
            'If the check is `file_exists`, write "must exist"; if the check is a `pattern-regex`, write "must match".',
            [
                'If the check is `file_exists`, write "must exist";',
                'if the check is a `pattern-regex`, write "must match".',
            ],
        ),
    ],
)
def test_a_sentence_is_cut_where_each_instruction_starts(sentence: str, pieces: list[str]) -> None:
    assert _pieces(sentence) == pieces


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_a_sentence_giving_two_instructions_maps_to_two_instructions() -> None:
    atoms = _mapped("# Rules\n\nValidate the input and sanitize the output.\n")
    assert _charged(atoms) == ["Validate the input", "and sanitize the output."]


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_a_condition_maps_with_the_instruction_it_leads_into() -> None:
    atoms = _mapped("# Rules\n\nRun the tests; if they fail, fix them.\n")
    assert [a.text for a in atoms] == ["Run the tests;", "if they fail, fix them."]


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_what_a_prohibition_lists_stays_prohibited() -> None:
    atoms = _mapped("# Rules\n\nDo not commit secrets, push credentials, or share tokens.\n")
    assert [(a.text, a.charge_value) for a in atoms] == [
        ("Do not commit secrets, push credentials, or share tokens.", -1)
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_a_comma_inside_a_code_span_does_not_cut_the_sentence() -> None:
    atoms = _mapped("# Rules\n\nRun `make build, make test` before merging.\n")
    assert [a.text for a in atoms] == ["Run `make build, make test` before merging."]


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_a_list_item_giving_two_instructions_maps_to_two_instructions() -> None:
    atoms = _mapped("# Rules\n\n- Pull the latest `main`, then run `uv run pytest`.\n")
    assert _charged(atoms) == ["Pull the latest `main`,", "then run `uv run pytest`."]


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_joined_instructions_map_to_as_many_instructions_as_their_split_form() -> None:
    joined = _mapped(
        "# Testing\n\nDo not mock the database; exercise the real ProductCache in the test, "
        "and give every assert statement a message.\n"
    )
    split = _mapped(
        "# Testing\n\nDo not mock the database. Exercise the real ProductCache in the test. "
        "Give every assert statement a message.\n"
    )
    assert len(_charged(joined)) == len(_charged(split)) == 3


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_the_mapped_sentence_is_reported_once_naming_its_instructions() -> None:
    atoms = _mapped("# Rules\n\nValidate the input and sanitize the output.\n")
    ruleset = RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(FileRecord(path="test.md", content_hash="sha256:abc"),),
        atoms=tuple(atoms),
        summary=RulesetSummary(n_atoms=len(atoms), n_charged=0, n_neutral=0),
    )
    [finding] = [f for f in run_client_checks(ruleset) if f.rule == "CORE:C:0058"]
    assert finding.line == 3
    assert "2 instructions" in finding.message
    assert '"Validate the input" / "and sanitize the output."' in finding.message
