"""Content-query checks report where the query found the problem."""

from __future__ import annotations

import pytest

from reporails_cli.core.lint.content_checker import run_content_checks
from reporails_cli.core.platform.dto.models import Category, Check, FileMatch, Rule, RuleType, Severity
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap, RulesetSummary


def _atom(path: str, line: int, text: str) -> Atom:
    return Atom(
        line=line,
        text=text,
        kind="excitation",
        charge="CONSTRAINT",
        charge_value=-1,
        modality="imperative",
        specificity="abstract",
        file_path=path,
    )


def _italic_rule() -> Rule:
    return Rule(
        id="CORE:E:0006",
        title="t",
        category=Category.EFFICIENCY,
        type=RuleType.MECHANICAL,
        severity=Severity.MEDIUM,
        match=FileMatch(),
        checks=[
            Check(
                id="c",
                type="content_query",
                query="has_non_italic_constraints",
                expect="absent",
                args={"message": "Constraint not in italics"},
            )
        ],
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_an_absent_check_reports_the_file_and_line_the_query_found() -> None:
    """The first file is clean; the violation is a prohibition on line 50 of the second. The finding
    points there, not at line 1 of the first file."""
    atoms = (_atom("a.md", 3, "*Do not skip the tests.*"), _atom("skills/b/SKILL.md", 50, "Do not skip the tests."))
    rm = RulesetMap(
        schema_version="1",
        embedding_model="none",
        generated_at="t",
        files=(
            FileRecord(path="a.md", content_hash="sha256:a"),
            FileRecord(path="skills/b/SKILL.md", content_hash="sha256:b"),
        ),
        atoms=atoms,
        summary=RulesetSummary(n_atoms=2, n_charged=2, n_neutral=0),
    )
    (finding,) = run_content_checks(rm, {"CORE:E:0006": _italic_rule()})
    assert (finding.file, finding.line) == ("skills/b/SKILL.md", 50)


def _map(atoms: tuple[Atom, ...], path: str = "CLAUDE.md") -> RulesetMap:
    return RulesetMap(
        schema_version="1",
        embedding_model="none",
        generated_at="t",
        files=(FileRecord(path=path, content_hash="sha256:a"),),
        atoms=atoms,
        summary=RulesetSummary(n_atoms=len(atoms), n_charged=len(atoms), n_neutral=0),
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_every_non_italic_prohibition_gets_its_own_finding() -> None:
    """Four plain prohibitions and one italic one: four findings, each on its own line."""
    atoms = (
        _atom("CLAUDE.md", 3, "Do not commit secrets."),
        _atom("CLAUDE.md", 5, "*Never edit generated files.*"),
        _atom("CLAUDE.md", 7, "Never edit generated files."),
        _atom("CLAUDE.md", 9, "- Do not skip the linter."),
        _atom("CLAUDE.md", 11, "Never force-push."),
    )
    findings = run_content_checks(_map(atoms), {"CORE:E:0006": _italic_rule()})
    assert [f.line for f in findings] == [3, 7, 9, 11]
    assert {f.rule for f in findings} == {"CORE:E:0006"}


def _heading(line: int, text: str, charge_value: int) -> Atom:
    return Atom(
        line=line,
        text=text,
        kind="heading",
        charge="DIRECTIVE" if charge_value else "NEUTRAL",
        charge_value=charge_value,
        modality="imperative",
        specificity="abstract",
        file_path="CLAUDE.md",
    )


def _heading_rule() -> Rule:
    return Rule(
        id="CORE:S:0039",
        title="t",
        category=Category.STRUCTURE,
        type=RuleType.MECHANICAL,
        severity=Severity.MEDIUM,
        match=FileMatch(),
        checks=[
            Check(
                id="h",
                type="content_query",
                query="has_charged_headings",
                expect="absent",
                args={"message": 'Instruction in heading: "{text}" — move it to the body.'},
            )
        ],
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_every_heading_with_an_instruction_gets_one_finding_of_the_same_shape() -> None:
    """The first heading is reported like the rest: same rule, severity and message shape with its text."""
    atoms = (
        _heading(1, "Project", 0),
        _heading(3, "Never commit secrets", -1),
        _heading(7, "Run the tests before pushing", 1),
        _heading(11, "Always format the code", 1),
    )
    findings = run_content_checks(_map(atoms), {"CORE:S:0039": _heading_rule()})
    assert [(f.line, f.rule, f.severity) for f in findings] == [
        (3, "CORE:S:0039", findings[0].severity),
        (7, "CORE:S:0039", findings[0].severity),
        (11, "CORE:S:0039", findings[0].severity),
    ]
    assert [f.message for f in findings] == [
        'Instruction in heading: "Never commit secrets" — move it to the body.',
        'Instruction in heading: "Run the tests before pushing" — move it to the body.',
        'Instruction in heading: "Always format the code" — move it to the body.',
    ]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_shipped_heading_rule_reports_a_mapped_file_no_file_type_claims() -> None:
    """A file the mapper read but no file type claims still gets its charged headings reported."""
    from pathlib import Path

    from reporails_cli.core.platform.adapters.registry import load_rules
    from reporails_cli.core.platform.dto.models import ClassifiedFile
    from reporails_cli.core.platform.policy.matching import is_wildcard_match

    rules = load_rules(rules_paths=[Path(__file__).parents[2] / "framework" / "rules"])
    rule = rules["CORE:S:0039"]
    assert rule.match is None or is_wildcard_match(rule.match)

    rm = RulesetMap(
        schema_version="1",
        embedding_model="none",
        generated_at="t",
        files=(
            FileRecord(path="/p/CLAUDE.md", content_hash="sha256:a"),
            FileRecord(path="/p/agents/nested/a.md", content_hash="sha256:b"),
        ),
        atoms=(_heading(2, "Phase 1: Fetch the data", 1).model_copy(update={"file_path": "/p/agents/nested/a.md"}),),
        summary=RulesetSummary(n_atoms=1, n_charged=1, n_neutral=0),
    )
    classified = [ClassifiedFile(path=Path("/p/CLAUDE.md"), file_type="main", properties={"format": "freeform"})]
    findings = run_content_checks(rm, {"CORE:S:0039": rule}, classified)
    assert [(f.file, f.line) for f in findings] == [("/p/agents/nested/a.md", 2)]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_bare_negative_heading_is_not_reported_but_a_full_sentence_heading_is() -> None:
    """`## Don'ts` labels a list of prohibitions; `## Never Push Directly to Main` is an instruction."""
    atoms = (
        _heading(1, "Don'ts", -1),
        _heading(5, "Must Not", -1),
        _heading(9, "Never Push Directly to Main", -1),
    )
    findings = run_content_checks(_map(atoms), {"CORE:S:0039": _heading_rule()})
    assert [(f.line, f.rule) for f in findings] == [(9, "CORE:S:0039")]
