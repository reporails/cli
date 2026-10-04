"""Formatting findings: false positives are not reported; real defects heal cannot rewrite stay reported."""

from __future__ import annotations

import pytest

from reporails_cli.core.heal.mechanical_fixers import (
    fix_bold_on_constraints,
    fix_italic_constraints,
    fix_unformatted_code,
)
from reporails_cli.core.lint.client_checks import run_client_checks
from reporails_cli.core.lint.content_queries import has_non_italic_constraints
from reporails_cli.core.mapper.annotate import check_specificity
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, RulesetMap, RulesetSummary


def _map(atom: Atom) -> RulesetMap:
    return RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(FileRecord(path="test.md", content_hash="sha256:abc"),),
        atoms=(atom,),
        summary=RulesetSummary(n_atoms=1, n_charged=1, n_neutral=0),
    )


def _atom(text: str, charge_value: int = 1, fmt: str = "prose", **kw: object) -> Atom:
    charge = {-1: "CONSTRAINT", 0: "NEUTRAL", 1: "DIRECTIVE"}[charge_value]
    return Atom(
        line=1,
        text=text,
        kind="excitation",
        charge=charge,
        charge_value=charge_value,
        modality="direct",
        specificity="named",
        format=fmt,
        file_path="test.md",
        bold_tokens=check_specificity(text)[4],
        **kw,  # type: ignore[arg-type]
    )


# (line, format, token, reported, heal fixes it)
_FORMAT_CASES = [
    ("Use JavaScript only for the browser bundle.", "prose", "JavaScript", False, False),
    ("See https://example.com/pytest/docs for details.", "prose", "example.com", False, False),
    ("Load the settings from @docs/pytest.md every time.", "prose", "pytest.md", False, False),
    ("See [the pytest guide](docs/guide.md) for details.", "prose", "pytest", False, False),
    ("| Use build.sh | run it |", "table", "build.sh", True, False),
    ("Run build.sh before every commit.", "prose", "build.sh", True, True),
    ("Open settings.json and edit it.", "prose", "settings.json", True, True),
]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("line", "fmt", "token", "reported", "fixed"), _FORMAT_CASES)
def test_format_finding(line: str, fmt: str, token: str, reported: bool, fixed: bool) -> None:
    atom = _atom(line, fmt=fmt, unformatted_code=[token])
    found = [f for f in run_client_checks(_map(atom)) if f.rule == "format"]
    lines = [line + "\n"]
    healed = fix_unformatted_code([atom], lines)
    assert bool(healed) is fixed, line
    assert bool(found) is reported, (line, [f.message for f in found])
    if not fixed:
        assert lines == [line + "\n"]


# Every one of these is a real defect: reported, and heal leaves the line as written.
_ITALIC_CASES = [
    ("Never push to main.", "prose", True),
    ("- Never commit secrets to the repo.", "list", False),
    ("1. Never commit secrets to the repo.", "numbered", False),
    ("| Never | commit secrets |", "table", False),
    ("**Never** commit secrets to the repo.", "prose", False),
    ("Keep it short. *Do not pad.*", "prose", False),
]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("line", "fmt", "fixed"), _ITALIC_CASES)
def test_italic_defect_is_reported_even_when_heal_leaves_it(line: str, fmt: str, fixed: bool) -> None:
    atom = _atom(line.removeprefix("- ").removeprefix("1. "), charge_value=-1, fmt=fmt)
    assert has_non_italic_constraints(_map(atom), "test.md").found is True, line
    lines = [line + "\n"]
    assert bool(fix_italic_constraints([atom], lines)) is fixed, line
    if not fixed:
        assert lines == [line + "\n"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fully_italic_constraint_is_not_reported() -> None:
    atom = _atom("*Never push to main.*", charge_value=-1)
    assert has_non_italic_constraints(_map(atom), "test.md").found is False


def _bold_reported(atom: Atom) -> list[str]:
    return [f.message for f in run_client_checks(_map(atom)) if f.rule == "bold"]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    "line",
    ["**EXCLUDE:**", "**Security note:** Never store the key."],
)
def test_bold_label_with_inner_colon_is_neither_reported_nor_rewritten(line: str) -> None:
    assert _bold_reported(_atom(line, charge_value=1)) == [], line
    atom = _atom(line, charge_value=-1)
    lines = [line + "\n"]
    assert fix_bold_on_constraints([atom], lines) == []
    assert lines == [line + "\n"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_label_and_second_bold_term_report_and_fix_only_the_second() -> None:
    line = "**Reason:** do not commit the **vault** file."
    atom = _atom(line, charge_value=-1)
    messages = _bold_reported(_atom(line, charge_value=1))
    assert len(messages) == 1
    assert "**vault**" in messages[0]
    assert "**Reason:**" not in messages[0]
    lines = [line + "\n"]
    assert len(fix_bold_on_constraints([atom], lines)) == 1
    assert lines == ["**Reason:** do not commit the *vault* file.\n"]


# (line, line after the fix, reported): the bold the check reports on a directive is the bold the
# fix changes on a constraint; a title label, a negation phrase and a label's colon are neither.
_BOLD_CASES = [
    ("Do **not** commit the vault.", "Do *not* commit the vault.", True),
    ("Never skip the **IMPORTANT** checks.", "Never skip the *IMPORTANT* checks.", True),
    ("Never skip the __vault__ file.", "Never skip the *vault* file.", True),
    ("**Fetch both sources** \u2014 never skip either.", "**Fetch both sources** \u2014 never skip either.", False),
    ("**Don't** commit the vault.", "**Don't** commit the vault.", False),
    ("**Never** commit the vault.", "**Never** commit the vault.", False),
    ("Never log **Rule**: it leaks.", "Never log **Rule**: it leaks.", False),
    ("**Keep the vault out of git.**", "**Keep the vault out of git.**", False),
]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("line", "after", "reported"), _BOLD_CASES)
def test_the_bold_the_check_reports_is_the_bold_the_fix_changes(line: str, after: str, reported: bool) -> None:
    assert bool(_bold_reported(_atom(line, charge_value=1))) is reported, line
    lines = [line + "\n"]
    fixes = fix_bold_on_constraints([_atom(line, charge_value=-1)], lines)
    assert bool(fixes) is reported, line
    assert lines == [after + "\n"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_constraint_is_italic_when_one_italic_run_covers_it() -> None:
    for text, italic in [
        ("*Never push.*", True),
        ("_Never push._", True),
        ("***Never push.***", True),
        ("*Never* push, *really*", False),
        ("**Never push.**", False),
        ("Never *push*.", False),
    ]:
        assert has_non_italic_constraints(_map(_atom(text, charge_value=-1)), "test.md").found is not italic, text


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("line", "term"),
    [
        ("Always forward `**kwargs` and `**opts` to the wrapper.", None),
        ("Always use **a *b* c** for tests.", "**a *b* c**"),
        ("Always touch the __database__ directly.", "**database**"),
    ],
)
def test_the_bold_finding_names_the_bold_tokens_of_the_atom(line: str, term: str | None) -> None:
    messages = _bold_reported(_atom(line, charge_value=1))
    assert (len(messages) == 1 and term in messages[0]) if term else messages == []
