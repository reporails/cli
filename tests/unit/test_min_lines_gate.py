"""Unit tests for the min_lines gate on deterministic checks (REQ-025 Phase B)."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.regex.runner import (
    _apply_min_lines_overrides,
    _emit_expect_findings,
    _file_below_min_lines,
    _load_check_expectations,
)


def _write_yml(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_check_expectations_extracts_min_lines(tmp_path: Path) -> None:
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
    expect, message, min_lines = _load_check_expectations([yml])
    assert expect == {"CORE.S.0013.pattern_check": "present"}
    assert message == {"CORE.S.0013.pattern_check": "missing scope"}
    assert min_lines == {"CORE.S.0013.pattern_check": 30}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_check_expectations_defaults_missing_min_lines_to_zero(tmp_path: Path) -> None:
    yml = _write_yml(
        tmp_path / "checks.yml",
        "checks:\n"
        "- id: CORE.S.0001.pattern\n"
        "  type: deterministic\n"
        "  pattern-regex: 'x'\n"
        "  expect: present\n"
        "  message: m\n",
    )
    _, _, min_lines = _load_check_expectations([yml])
    assert "CORE.S.0001.pattern" not in min_lines  # absent = no gate


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_apply_min_lines_overrides_uses_rule_id(tmp_path: Path) -> None:
    expect_map = {"CORE.S.0013.pattern_check": "present"}
    base = {"CORE.S.0013.pattern_check": 30}
    overrides = {"CORE:S:0013": 50}
    merged = _apply_min_lines_overrides(base, expect_map, overrides)
    assert merged["CORE.S.0013.pattern_check"] == 50


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

    expect_map = {"CORE.S.0013.pattern_check": "present"}
    message_map = {"CORE.S.0013.pattern_check": "missing scope"}
    matched_pairs: set[tuple[str, str]] = set()  # neither file matched the pattern
    findings = _emit_expect_findings(
        expect_map=expect_map,
        message_map=message_map,
        matched_pairs=matched_pairs,
        match_details={},
        scanned_files=["tiny.md", "long.md"],
        min_lines_map={"CORE.S.0013.pattern_check": 30},
        scan_root=tmp_path,
    )
    files_with_findings = {f.file for f in findings}
    assert "tiny.md" not in files_with_findings  # gated out
    assert "long.md" in files_with_findings  # fires normally


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_emit_expect_findings_no_gate_when_min_lines_zero(tmp_path: Path) -> None:
    (tmp_path / "tiny.md").write_text("# tiny\n", encoding="utf-8")
    expect_map = {"CORE.S.0013.pattern_check": "present"}
    findings = _emit_expect_findings(
        expect_map=expect_map,
        message_map={"CORE.S.0013.pattern_check": "missing"},
        matched_pairs=set(),
        match_details={},
        scanned_files=["tiny.md"],
        min_lines_map=None,
        scan_root=tmp_path,
    )
    assert len(findings) == 1
