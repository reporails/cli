"""One Instruction Per Sentence (CORE:C:0058): a sentence holding more than one instruction."""

from __future__ import annotations

import pytest

from reporails_cli.core.lint.client_checks import run_client_checks
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap, RulesetSummary

RULE = "CORE:C:0058"


def _map(atoms: list[Atom]) -> RulesetMap:
    return RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(FileRecord(path="test.md", content_hash="sha256:abc"),),
        atoms=tuple(atoms),
        summary=RulesetSummary(n_atoms=len(atoms), n_charged=0, n_neutral=0),
    )


def _atom(line: int, text: str, charge_value: int = 1, fmt: str = "prose", kind: str = "excitation") -> Atom:
    charge = {-1: "CONSTRAINT", 0: "NEUTRAL", 1: "DIRECTIVE"}[charge_value]
    return Atom(
        line=line,
        text=text,
        kind=kind,
        charge=charge,
        charge_value=charge_value,
        modality="direct" if charge_value else "none",
        specificity="abstract",
        format=fmt,
        file_path="test.md",
    )


def _packed(atoms: list[Atom]) -> list[tuple[int, str]]:
    return [(f.line, f.message) for f in run_client_checks(_map(atoms)) if f.rule == RULE]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_sentence_read_as_two_instructions_is_reported_once_naming_them() -> None:
    found = _packed([_atom(3, "Validate the input"), _atom(3, "and sanitize the output.")])
    assert [line for line, _ in found] == [3]
    [(_, message)] = found
    assert "2 instructions" in message and '"Validate the input" / "and sanitize the output."' in message


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_label_read_apart_from_its_instruction_is_not_a_second_instruction() -> None:
    found = _packed([_atom(6, "`feedback_no_kill.md` —"), _atom(6, "Never kill a process you did not spawn.", -1)])
    assert found == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_an_emphasized_sentence_read_as_two_instructions_is_reported() -> None:
    found = _packed(
        [_atom(4, "*Do not approve a direct filing;*", -1), _atom(4, "*do not pre-empt the architect.*", -1)]
    )
    assert [line for line, _ in found] == [4]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_the_same_instructions_in_their_own_sentences_are_not_reported() -> None:
    assert _packed([_atom(3, "Validate the input."), _atom(3, "Sanitize the output.")]) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_sentence_read_as_one_instruction_is_not_reported() -> None:
    assert _packed([_atom(3, "Use `uv` to install packages, add dependencies, and run scripts.")]) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_prohibition_and_a_command_in_one_sentence_are_reported() -> None:
    found = _packed([_atom(5, "Only fetch the temperature,"), _atom(5, "do not perform any transformations.", -1)])
    assert [line for line, _ in found] == [5]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_sentence_wrapped_onto_the_next_line_is_read_whole() -> None:
    found = _packed([_atom(7, "Modify the parser in `parse.py`,"), _atom(8, "then run `pytest tests/` on it.")])
    assert [line for line, _ in found] == [7]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_wrapped_sentence_names_the_instructions_it_gives() -> None:
    atoms = [
        _atom(7, "Install dependencies with `uv sync`, run"),
        _atom(8, "`uv run pytest`,", charge_value=0),
        _atom(8, "and commit the lockfile."),
    ]
    [(_, message)] = _packed(atoms)
    assert "3 instructions" in message
    assert '"Install dependencies with `uv sync`," / "run `uv run pytest`," / "and commit the lockfile."' in message


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_bold_lead_label_is_left_out_of_the_named_instructions() -> None:
    atoms = [
        _atom(3, "**Category reclassification**: determine the next slot,"),
        _atom(3, "move the rule directory with `git mv`,"),
        _atom(3, "update every check ID prefix."),
    ]
    [(_, message)] = _packed(atoms)
    assert "3 instructions" in message
    assert '("determine the next slot," / "move the rule directory with `git mv`," / "update every' in message


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_task_checkbox_and_bold_before_punctuation_are_left_out_of_the_names() -> None:
    [(_, message)] = _packed([_atom(3, "[ ] Install it with **uv**,"), _atom(3, "then run the tests.")])
    assert '("Install it with uv," / "then run the tests.")' in message


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_an_identifier_outside_backticks_is_named_as_written() -> None:
    [(_, message)] = _packed([_atom(3, "Delete build_*.log files,"), _atom(3, "then run the tests.")])
    assert '("Delete build_*.log files," / "then run the tests.")' in message


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_code_span_is_named_as_written() -> None:
    [(_, message)] = _packed([_atom(3, "Write notes at `docs/*.md`,"), _atom(3, "then run `lint_*`.")])
    assert '("Write notes at `docs/*.md`," / "then run `lint_*`.")' in message


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_instructions_on_lines_with_no_end_mark_are_not_one_sentence() -> None:
    found = _packed([_atom(3, "Keep functions small"), _atom(4, "Prefer composition over inheritance")])
    assert found == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_statement_beside_an_instruction_is_not_counted() -> None:
    found = _packed([_atom(3, "The tool reads the file,", charge_value=0), _atom(3, "so run it first.")])
    assert found == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_headings_and_code_are_not_read() -> None:
    atoms = [
        _atom(1, "Build and test the project", kind="heading", fmt="heading"),
        _atom(2, "make build;", fmt="code_block"),
        _atom(2, "make test", fmt="code_block"),
    ]
    assert _packed(atoms) == []
