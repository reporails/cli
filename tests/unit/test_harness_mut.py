"""Mutation-kill tests for core.lint.harness — deterministic/violation paths.

Each test drives `run_rule` with a hand-built `RuleInfo` + fixtures whose correct
outcome a specific injected operator bug would flip (a wrong engine_ok default, a
mis-selected pattern rule, a swapped expect gate, a wrong violation/CheckRun
flag). The assertion reddens when that bug returns.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.harness import HarnessStatus, RuleInfo, fixture_mapper, run_rule
from reporails_cli.core.platform.dto.models import FileTypeDeclaration
from tests.fake_models import no_models

# ── Helpers ──────────────────────────────────────────────────────────

_MAIN = [FileTypeDeclaration(name="main", patterns=("**/CLAUDE.md",), required=True, properties={})]


def _rule_dir(tmp_path: Path, slug: str) -> Path:
    d = tmp_path / "core" / slug
    d.mkdir(parents=True)
    return d


def _rule_md(rule_dir: Path, rule_id: str = "CORE:S:0001") -> None:
    """A registry-loadable rule.md; checks live only in checks.yml, as in the real rules."""
    (rule_dir / "rule.md").write_text(
        f"---\nid: {rule_id}\nslug: {rule_dir.name}\ntitle: T\ncategory: structure\n"
        "type: deterministic\nseverity: medium\nbacked_by: [x]\nmatch: {type: main}\n---\n# T\n\nBody.\n"
    )


def _pass(rule_dir: Path, content: str, name: str = "CLAUDE.md") -> None:
    d = rule_dir / "tests" / "pass"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(content)


def _fail(rule_dir: Path, content: str, name: str = "CLAUDE.md") -> None:
    d = rule_dir / "tests" / "fail"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(content)


def _info(rule_dir: Path, checks: list[dict], rule_id: str = "CORE:S:0001") -> RuleInfo:
    return RuleInfo(
        rule_id=rule_id,
        slug=rule_dir.name,
        title="T",
        category="structure",
        checks=checks,
        rule_dir=rule_dir,
    )


def _det_check(check_id: str = "CORE.S.0001.check", expect: str = "absent") -> dict:
    return {
        "id": check_id,
        "type": "deterministic",
        "severity": "medium",
        "expect": expect,
        "pattern-regex": "x",
    }


def _checks_yml(rule_dir: Path, rules_yaml: str) -> None:
    (rule_dir / "checks.yml").write_text(rules_yaml)


def _one_pattern(check_id: str, pattern: str) -> str:
    return (
        "checks:\n"
        f"- id: {check_id}\n"
        "  message: m\n"
        "  severity: medium\n"
        "  paths:\n    include: ['**/*.md']\n"
        f"  pattern-regex: '{pattern}'\n"
    )


def _fail_run(result):
    return next(r for r in result.check_runs if r.fixture == "fail")


def _pass_run(result):
    return next(r for r in result.check_runs if r.fixture == "pass")


# ── expect gate (L297) ───────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_expect_present_without_finding_fails(tmp_path: Path) -> None:
    """expect=present + no finding on the pass fixture → FAILED
    (kills L297 `ok and count > 0` -> `or`)."""
    rd = _rule_dir(tmp_path, "present-nofind")
    _pass(rd, "# nothing relevant\n")
    _checks_yml(rd, _one_pattern("CORE.S.0001.check", "Commands"))
    result = run_rule(_info(rd, [_det_check(expect="present")]), [], fixture_mapper(no_models()))
    assert result.status == HarnessStatus.FAILED


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_expect_absent_with_finding_fails(tmp_path: Path) -> None:
    """expect=absent + a finding on the pass fixture → FAILED
    (kills L297 `ok and count == 0` -> `or`)."""
    rd = _rule_dir(tmp_path, "absent-find")
    _pass(rd, "# Commands appear here\n")
    _checks_yml(rd, _one_pattern("CORE.S.0001.check", "Commands"))
    result = run_rule(_info(rd, [_det_check(expect="absent")]), [], fixture_mapper(no_models()))
    assert result.status == HarnessStatus.FAILED


# ── fail-fixture violation accounting (L227) + CheckRun flags ─────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fail_fixture_without_violation_is_failed(tmp_path: Path) -> None:
    """A fail fixture where the check finds no violation → FAILED
    (kills L227 fail_violation_found=False -> True), and the fail CheckRun is
    reported passed=True (kills L329 True->False)."""
    rd = _rule_dir(tmp_path, "no-violation")
    _fail(rd, "# has the file\n")  # fail fixture only; file_exists will pass here
    check = {
        "id": "CORE.S.0001.check",
        "type": "mechanical",
        "severity": "medium",
        "check": "file_exists",
        "args": {"path": "**/*.md"},
    }
    result = run_rule(_info(rd, [check]), [], fixture_mapper(no_models()))
    assert result.status == HarnessStatus.FAILED
    assert _fail_run(result).passed is True


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_deterministic_fail_checkrun_is_passed_true(tmp_path: Path) -> None:
    """The deterministic fail CheckRun is constructed passed=True (kills L334 True->False)."""
    rd = _rule_dir(tmp_path, "det-fail-run")
    _fail(rd, "# Commands here\n")
    _checks_yml(rd, _one_pattern("CORE.S.0001.check", "Commands"))
    result = run_rule(_info(rd, [_det_check(expect="present")]), [], fixture_mapper(no_models()))
    assert _fail_run(result).passed is True


# ── content_query path (L300, L303, L336, L337) ──────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_content_query_passes_on_pass_fixture(tmp_path: Path) -> None:
    """A content_query check is skipped-as-passed on the pass fixture
    (kills L300 == -> != and L303 CheckRun True->False)."""
    rd = _rule_dir(tmp_path, "cq-pass")
    _pass(rd, "# ok\n")
    check = {"id": "CORE.S.0001.cq", "type": "content_query", "severity": "medium"}
    result = run_rule(_info(rd, [check]), [], fixture_mapper(no_models()))
    assert result.status == HarnessStatus.PASSED
    run = _pass_run(result)
    assert run.passed is True
    assert "content_query" in run.message


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_content_query_fail_fixture_finds_no_violation(tmp_path: Path) -> None:
    """content_query on a fail fixture is not a violation → FAILED
    (kills L337 False->True), and the run keeps the content_query message
    (kills L336 == -> !=)."""
    rd = _rule_dir(tmp_path, "cq-fail")
    _fail(rd, "# ok\n")
    check = {"id": "CORE.S.0001.cq", "type": "content_query", "severity": "medium"}
    result = run_rule(_info(rd, [check]), [], fixture_mapper(no_models()))
    assert result.status == HarnessStatus.FAILED
    assert "content_query" in _fail_run(result).message


# ── unknown check type (L307, L339) ──────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_excluded_fixture_file_is_not_scanned(tmp_path: Path) -> None:
    """A `.gitkeep` fixture file is filtered out before regex scanning, so its
    content produces no finding (kills L124 `is_file() and name not in excludes`
    -> `or`, which would let the excluded file through)."""
    rd = _rule_dir(tmp_path, "excluded-scan")
    pd = rd / "tests" / "pass"
    pd.mkdir(parents=True)
    (pd / "CLAUDE.md").write_text("# nothing relevant\n")  # real file, no match
    (pd / ".gitkeep").write_text("Commands appear here\n")  # excluded file, has match
    _checks_yml(
        rd,
        "checks:\n"
        "- id: CORE.S.0001.check\n"
        "  message: m\n  severity: medium\n"
        "  paths:\n    include: ['**/*']\n  pattern-regex: 'Commands'\n",
    )
    # expect=present: the match lives only in the excluded file, so a correctly
    # filtered scan finds nothing → FAILED; letting .gitkeep through → PASSED.
    result = run_rule(_info(rd, [_det_check(expect="present")]), [], fixture_mapper(no_models()))
    assert result.status == HarnessStatus.FAILED
