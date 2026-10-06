"""Mutation-kill tests for core.lint.harness — deterministic/violation paths.

Each test drives `run_rule` with a hand-built `RuleInfo` + fixtures whose correct
outcome a specific injected operator bug would flip (a wrong engine_ok default, a
mis-selected pattern rule, a swapped expect gate, a wrong violation/CheckRun
flag). The assertion reddens when that bug returns.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.harness import HarnessStatus, RuleInfo, run_rule

# ── Helpers ──────────────────────────────────────────────────────────


def _rule_dir(tmp_path: Path, slug: str) -> Path:
    d = tmp_path / "core" / slug
    d.mkdir(parents=True)
    return d


def _pass(rule_dir: Path, content: str, name: str = "CLAUDE.md") -> None:
    d = rule_dir / "tests" / "pass"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(content)


def _fail(rule_dir: Path, content: str, name: str = "CLAUDE.md") -> None:
    d = rule_dir / "tests" / "fail"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(content)


def _info(rule_dir: Path, checks: list[dict], rule_id: str = "CORE:S:0001", rtype: str = "deterministic") -> RuleInfo:
    return RuleInfo(
        rule_id=rule_id,
        slug=rule_dir.name,
        title="T",
        category="structure",
        rule_type=rtype,
        match={},
        checks=checks,
        rule_dir=rule_dir,
        checks_yml=rule_dir / "checks.yml",
    )


def _det_check(check_id: str = "CORE.S.0001.check", expect: str = "absent") -> dict:
    return {"id": check_id, "type": "deterministic", "severity": "medium", "expect": expect, "name": "d"}


def _checks_yml(rule_dir: Path, rules_yaml: str) -> None:
    (rule_dir / "checks.yml").write_text(rules_yaml)


def _one_pattern(check_id: str, pattern: str) -> str:
    return (
        "checks:\n"
        f"- id: {check_id}\n"
        "  message: m\n"
        "  severity: WARNING\n"
        "  languages: [generic]\n"
        "  paths:\n    include: ['**/*.md']\n"
        f"  pattern-regex: '{pattern}'\n"
    )


def _fail_run(result):
    return next(r for r in result.check_runs if r.fixture == "fail")


def _pass_run(result):
    return next(r for r in result.check_runs if r.fixture == "pass")


# ── engine_ok defaults in _run_deterministic_check ───────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_missing_checks_yml_is_engine_failure(tmp_path: Path) -> None:
    """No checks.yml → engine_ok=False → the pass fixture fails (kills L89 False->True)."""
    rd = _rule_dir(tmp_path, "no-yml")
    _pass(rd, "# ok\n")  # no checks.yml written
    result = run_rule(_info(rd, [_det_check(expect="absent")]), [])
    assert result.status == HarnessStatus.FAILED


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_empty_checks_yml_is_engine_failure(tmp_path: Path) -> None:
    """checks.yml with `checks: []` → engine_ok=False (kills L98 False->True)."""
    rd = _rule_dir(tmp_path, "empty-yml")
    _pass(rd, "# ok\n")
    _checks_yml(rd, "checks: []\n")
    result = run_rule(_info(rd, [_det_check(expect="absent")]), [])
    assert result.status == HarnessStatus.FAILED


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_no_matching_rule_reports_no_pattern(tmp_path: Path) -> None:
    """2 rules, none matching the check id → no pattern → engine failure
    (kills L109 and->or fallback and L113 False->True)."""
    rd = _rule_dir(tmp_path, "no-match")
    _pass(rd, "# ok\n")
    _checks_yml(
        rd,
        "checks:\n"
        "- id: CORE.S.9991.other\n"
        "  message: m\n  severity: WARNING\n  languages: [generic]\n"
        "  paths:\n    include: ['**/*.md']\n  pattern-regex: 'ZZZNOMATCH'\n"
        "- id: CORE.S.9992.other2\n"
        "  message: m\n  severity: WARNING\n  languages: [generic]\n"
        "  paths:\n    include: ['**/*.md']\n  pattern-regex: 'QQQNOMATCH'\n",
    )
    result = run_rule(_info(rd, [_det_check(check_id="CORE.S.0001.check", expect="absent")]), [])
    assert result.status == HarnessStatus.FAILED


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_single_nonmatching_rule_falls_back(tmp_path: Path) -> None:
    """A single rule with a non-matching id is still used via fallback
    (kills L109 == -> != so the single-rule fallback survives)."""
    rd = _rule_dir(tmp_path, "fallback")
    _pass(rd, "# Commands here\n")
    _checks_yml(rd, _one_pattern("CORE.S.9990.other", "Commands"))
    # expect=present: fallback runs the rule → finding → pass; no fallback → fail
    result = run_rule(_info(rd, [_det_check(check_id="CORE.S.0001.check", expect="present")]), [])
    assert result.status == HarnessStatus.PASSED


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_matching_rule_selected_by_id(tmp_path: Path) -> None:
    """The rule whose id equals the check id is the one run (kills L105 == -> !=)."""
    rd = _rule_dir(tmp_path, "by-id")
    _pass(rd, "# Commands here\n")
    _checks_yml(
        rd,
        "checks:\n"
        "- id: CORE.S.0001.check\n"  # WRONG rule: pattern would not fire
        "  message: m\n  severity: WARNING\n  languages: [generic]\n"
        "  paths:\n    include: ['**/*.md']\n  pattern-regex: 'ZZZNOMATCH'\n"
        "- id: CORE.S.0002.check\n"  # RIGHT rule: matches the check id + fixture
        "  message: m\n  severity: WARNING\n  languages: [generic]\n"
        "  paths:\n    include: ['**/*.md']\n  pattern-regex: 'Commands'\n",
    )
    result = run_rule(_info(rd, [_det_check(check_id="CORE.S.0002.check", expect="present")]), [])
    assert result.status == HarnessStatus.PASSED


# ── expect gate (L297) ───────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_expect_present_without_finding_fails(tmp_path: Path) -> None:
    """expect=present + no finding on the pass fixture → FAILED
    (kills L297 `ok and count > 0` -> `or`)."""
    rd = _rule_dir(tmp_path, "present-nofind")
    _pass(rd, "# nothing relevant\n")
    _checks_yml(rd, _one_pattern("CORE.S.0001.check", "Commands"))
    result = run_rule(_info(rd, [_det_check(expect="present")]), [])
    assert result.status == HarnessStatus.FAILED


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_expect_absent_with_finding_fails(tmp_path: Path) -> None:
    """expect=absent + a finding on the pass fixture → FAILED
    (kills L297 `ok and count == 0` -> `or`)."""
    rd = _rule_dir(tmp_path, "absent-find")
    _pass(rd, "# Commands appear here\n")
    _checks_yml(rd, _one_pattern("CORE.S.0001.check", "Commands"))
    result = run_rule(_info(rd, [_det_check(expect="absent")]), [])
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
    result = run_rule(_info(rd, [check], rtype="mechanical"), [])
    assert result.status == HarnessStatus.FAILED
    assert _fail_run(result).passed is True


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_deterministic_fail_checkrun_is_passed_true(tmp_path: Path) -> None:
    """The deterministic fail CheckRun is constructed passed=True (kills L334 True->False)."""
    rd = _rule_dir(tmp_path, "det-fail-run")
    _fail(rd, "# Commands here\n")
    _checks_yml(rd, _one_pattern("CORE.S.0001.check", "Commands"))
    result = run_rule(_info(rd, [_det_check(expect="present")]), [])
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
    result = run_rule(_info(rd, [check], rtype="content_query"), [])
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
    result = run_rule(_info(rd, [check], rtype="content_query"), [])
    assert result.status == HarnessStatus.FAILED
    assert "content_query" in _fail_run(result).message


# ── unknown check type (L307, L339) ──────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_unknown_check_type_pass_fixture_fails(tmp_path: Path) -> None:
    """An unknown check type does not pass the pass fixture → FAILED
    (kills L307 False->True and its CheckRun flag)."""
    rd = _rule_dir(tmp_path, "unknown-pass")
    _pass(rd, "# ok\n")
    check = {"id": "CORE.S.0001.x", "type": "bogus", "severity": "medium"}
    result = run_rule(_info(rd, [check], rtype="bogus"), [])
    assert result.status == HarnessStatus.FAILED
    assert _pass_run(result).passed is False


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
        "  message: m\n  severity: WARNING\n  languages: [generic]\n"
        "  paths:\n    include: ['**/*']\n  pattern-regex: 'Commands'\n",
    )
    # expect=present: the match lives only in the excluded file, so a correctly
    # filtered scan finds nothing → FAILED; letting .gitkeep through → PASSED.
    result = run_rule(_info(rd, [_det_check(expect="present")]), [])
    assert result.status == HarnessStatus.FAILED


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_unknown_check_type_fail_fixture_no_violation(tmp_path: Path) -> None:
    """An unknown check type finds no violation on the fail fixture → FAILED
    (kills L339 violation False->True and its CheckRun flag False->True)."""
    rd = _rule_dir(tmp_path, "unknown-fail")
    _fail(rd, "# ok\n")
    check = {"id": "CORE.S.0001.x", "type": "bogus", "severity": "medium"}
    result = run_rule(_info(rd, [check], rtype="bogus"), [])
    assert result.status == HarnessStatus.FAILED
    assert _fail_run(result).passed is False
