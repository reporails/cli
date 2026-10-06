"""Unit tests for the min_lines gate on deterministic checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.regex.compiler import CompiledCheck, compile_rules
from reporails_cli.core.lint.regex.runner import (
    _apply_min_lines_overrides,
    _emit_expect_findings,
    _file_below_min_lines,
)


def _write_yml(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _check(check_id: str, *, message: str = "", min_lines: int = 0, every_match: bool = False) -> CompiledCheck:
    """A compiled check carrying only what the expect findings read."""
    return CompiledCheck(
        id=check_id,
        message=message,
        severity="warning",
        patterns=(),
        negative_patterns=(),
        either_patterns=(),
        path_includes=(),
        every_match=every_match,
        min_lines=min_lines,
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_compiled_check_carries_min_lines(tmp_path: Path) -> None:
    yml = _write_yml(
        tmp_path / "checks.yml",
        "checks:\n"
        "- id: CORE.S.0013.pattern_check\n"
        "  type: deterministic\n"
        "  pattern-regex: 'x'\n"
        "  expect: present\n"
        "  min_lines: 30\n"
        "  message: missing scope\n",
    )
    (check,) = compile_rules([yml]).checks
    assert check.every_match is False
    assert check.message == "missing scope"
    assert check.min_lines == 30


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_compiled_check_defaults_missing_min_lines_to_zero(tmp_path: Path) -> None:
    yml = _write_yml(
        tmp_path / "checks.yml",
        "checks:\n"
        "- id: CORE.S.0001.pattern\n"
        "  type: deterministic\n"
        "  pattern-regex: 'x'\n"
        "  expect: present\n"
        "  message: m\n",
    )
    (check,) = compile_rules([yml]).checks
    assert check.min_lines == 0  # absent = no gate


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_apply_min_lines_overrides_uses_rule_id(tmp_path: Path) -> None:
    base = [_check("CORE.S.0013.pattern_check", min_lines=30), _check("CORE.S.0001.other", min_lines=30)]
    merged = _apply_min_lines_overrides(base, {"CORE:S:0013": 50})
    assert [c.min_lines for c in merged] == [50, 30]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_file_below_min_lines_short_file(tmp_path: Path) -> None:
    short = tmp_path / "rule.md"
    short.write_text("---\nline 1\nline 2\n---\n# rule\n", encoding="utf-8")
    assert _file_below_min_lines("rule.md", 30, tmp_path) is True


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_file_below_min_lines_long_file(tmp_path: Path) -> None:
    long_file = tmp_path / "rule.md"
    long_file.write_text("\n".join(f"line {i}" for i in range(50)), encoding="utf-8")
    assert _file_below_min_lines("rule.md", 30, tmp_path) is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_file_below_min_lines_disabled_when_zero(tmp_path: Path) -> None:
    short = tmp_path / "rule.md"
    short.write_text("x\n", encoding="utf-8")
    assert _file_below_min_lines("rule.md", 0, tmp_path) is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_emit_expect_findings_skips_short_files_when_present_missing(tmp_path: Path) -> None:
    # tiny.md is below threshold; long.md is above.
    (tmp_path / "tiny.md").write_text("# tiny\n", encoding="utf-8")
    (tmp_path / "long.md").write_text("\n".join(f"L{i}" for i in range(50)), encoding="utf-8")

    matched_pairs: set[tuple[str, str]] = set()  # neither file matched the pattern
    findings = _emit_expect_findings(
        [_check("CORE.S.0013.pattern_check", message="missing scope", min_lines=30)],
        matched_pairs=matched_pairs,
        match_details={},
        scanned_files=["tiny.md", "long.md"],
        scan_root=tmp_path,
    )
    files_with_findings = {f.file for f in findings}
    assert "tiny.md" not in files_with_findings  # gated out
    assert "long.md" in files_with_findings  # fires normally


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_emit_expect_findings_no_gate_when_min_lines_zero(tmp_path: Path) -> None:
    (tmp_path / "tiny.md").write_text("# tiny\n", encoding="utf-8")
    findings = _emit_expect_findings(
        [_check("CORE.S.0013.pattern_check", message="missing")],
        matched_pairs=set(),
        match_details={},
        scanned_files=["tiny.md"],
        scan_root=tmp_path,
    )
    assert len(findings) == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_pattern_finding_names_the_check_that_found_it() -> None:
    check = "CLAUDE.S.0012.uses_globs_key"
    findings = _emit_expect_findings(
        [_check(check, message="uses globs", every_match=True)],
        matched_pairs={(check, "a.md")},
        match_details={(check, "a.md"): [(2, "globs:", "")]},
        scanned_files=["a.md"],
    )
    assert [(f.rule, f.line, f.check_id) for f in findings] == [("CLAUDE:S:0012", 2, check)]
