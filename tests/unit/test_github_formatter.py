"""Tests for the GitHub Actions workflow command formatter.

Tests cover:
- Severity mapping (critical/high → error, medium/low → warning)
- File:line parsing from violation location
- Special character escaping (colons, commas, newlines)
- Empty violations → no annotations
- JSON line is valid and contains score/level
"""

from __future__ import annotations

import json

from reporails_cli.core.models import (
    FrictionEstimate,
    Level,
    ScanDelta,
    Severity,
    ValidationResult,
    Violation,
)
from reporails_cli.formatters import github as github_formatter


def _make_violation(
    rule_id: str = "CORE:S:0005",
    rule_title: str = "Instruction File Size Limit",
    location: str = "CLAUDE.md:45",
    message: str = "File exceeds recommended size",
    severity: Severity = Severity.HIGH,
    check_id: str = "CORE:S:0005:check:0001",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        rule_title=rule_title,
        location=location,
        message=message,
        severity=severity,
        check_id=check_id,
    )


def _make_result(
    violations: tuple[Violation, ...] = (),
    score: float = 7.5,
    level: Level = Level.L3,
) -> ValidationResult:
    return ValidationResult(
        score=score,
        level=level,
        violations=violations,
        judgment_requests=(),
        rules_checked=10,
        rules_passed=10 - len(violations),
        rules_failed=len(violations),
        feature_summary="Root file",
        friction=FrictionEstimate(level="small"),
    )


class TestSeverityMapping:
    """Test _severity_to_command mapping."""

    def test_critical_maps_to_error(self) -> None:
        assert github_formatter._severity_to_command(Severity.CRITICAL) == "error"

    def test_high_maps_to_error(self) -> None:
        assert github_formatter._severity_to_command(Severity.HIGH) == "error"

    def test_medium_maps_to_warning(self) -> None:
        assert github_formatter._severity_to_command(Severity.MEDIUM) == "warning"

    def test_low_maps_to_warning(self) -> None:
        assert github_formatter._severity_to_command(Severity.LOW) == "warning"


class TestLocationParsing:
    """Test file:line parsing from violation location."""

    def test_standard_file_line(self) -> None:
        v = _make_violation(location="CLAUDE.md:45")
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        assert "file=CLAUDE.md,line=45" in output

    def test_file_only_defaults_to_line_1(self) -> None:
        v = _make_violation(location="CLAUDE.md")
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        assert "file=CLAUDE.md,line=1" in output

    def test_path_with_directory(self) -> None:
        v = _make_violation(location=".claude/rules/testing.md:12")
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        assert "file=.claude/rules/testing.md,line=12" in output

    def test_non_numeric_line_defaults_to_1(self) -> None:
        v = _make_violation(location="CLAUDE.md:abc")
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        assert "file=CLAUDE.md%3Aabc,line=1" in output


class TestEscaping:
    """Test special character escaping in workflow commands."""

    def test_escape_property_colon(self) -> None:
        assert github_formatter._escape_workflow_property("a:b") == "a%3Ab"

    def test_escape_property_comma(self) -> None:
        assert github_formatter._escape_workflow_property("a,b") == "a%2Cb"

    def test_escape_property_percent(self) -> None:
        assert github_formatter._escape_workflow_property("100%") == "100%25"

    def test_escape_property_newline(self) -> None:
        assert github_formatter._escape_workflow_property("a\nb") == "a%0Ab"

    def test_escape_property_carriage_return(self) -> None:
        assert github_formatter._escape_workflow_property("a\rb") == "a%0Db"

    def test_escape_data_percent(self) -> None:
        assert github_formatter._escape_workflow_data("100%") == "100%25"

    def test_escape_data_newline(self) -> None:
        assert github_formatter._escape_workflow_data("line1\nline2") == "line1%0Aline2"

    def test_escape_data_preserves_colon(self) -> None:
        """Data (message body) does NOT escape colons — only properties do."""
        assert github_formatter._escape_workflow_data("a:b") == "a:b"

    def test_title_with_special_chars(self) -> None:
        v = _make_violation(
            rule_id="CORE:S:0012",
            rule_title="Reusable Skills Over Repeated Prompts",
            message="Multi-step procedure found inline",
        )
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        # Colons in rule_id should be escaped in title property
        assert "[CORE%3AS%3A0012]" in output

    def test_percent_in_message_escaped_before_other_chars(self) -> None:
        """Percent must be escaped first to avoid double-escaping."""
        result = github_formatter._escape_workflow_data("100%\n")
        assert result == "100%25%0A"

    def test_percent_in_property_escaped_before_other_chars(self) -> None:
        result = github_formatter._escape_workflow_property("100%\n:")
        assert result == "100%25%0A%3A"


class TestAnnotations:
    """Test format_annotations output."""

    def test_empty_violations_returns_empty(self) -> None:
        result = _make_result(violations=())
        output = github_formatter.format_annotations(result)
        assert output == ""

    def test_single_violation_format(self) -> None:
        v = _make_violation(
            rule_id="CORE:S:0012",
            rule_title="Reusable Skills",
            location="CLAUDE.md:45",
            message="Multi-step procedure found",
            severity=Severity.HIGH,
        )
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        assert output.startswith("::error ")
        assert "file=CLAUDE.md" in output
        assert "line=45" in output
        assert "Multi-step procedure found" in output

    def test_multiple_violations_one_per_line(self) -> None:
        v1 = _make_violation(severity=Severity.HIGH, location="a.md:1")
        v2 = _make_violation(severity=Severity.MEDIUM, location="b.md:2")
        result = _make_result(violations=(v1, v2))
        output = github_formatter.format_annotations(result)
        lines = output.strip().split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("::error ")
        assert lines[1].startswith("::warning ")

    def test_warning_severity(self) -> None:
        v = _make_violation(severity=Severity.LOW)
        result = _make_result(violations=(v,))
        output = github_formatter.format_annotations(result)
        assert output.startswith("::warning ")


class TestFormatResult:
    """Test full format_result output (annotations + JSON)."""

    def test_json_line_is_last(self) -> None:
        v = _make_violation()
        result = _make_result(violations=(v,))
        output = github_formatter.format_result(result)
        last_line = output.strip().split("\n")[-1]
        data = json.loads(last_line)
        assert "score" in data
        assert "level" in data

    def test_json_line_contains_score_and_level(self) -> None:
        result = _make_result(score=8.5, level=Level.L4)
        output = github_formatter.format_result(result)
        last_line = output.strip().split("\n")[-1]
        data = json.loads(last_line)
        assert data["score"] == 8.5
        assert data["level"] == "L4"

    def test_empty_violations_only_json(self) -> None:
        result = _make_result(violations=())
        output = github_formatter.format_result(result)
        lines = output.strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["violations"] == []

    def test_delta_included_in_json(self) -> None:
        result = _make_result(score=7.5)
        delta = ScanDelta(
            score_delta=0.5,
            level_previous="L2",
            level_improved=True,
            violations_delta=-2,
        )
        output = github_formatter.format_result(result, delta)
        last_line = output.strip().split("\n")[-1]
        data = json.loads(last_line)
        assert data["score_delta"] == 0.5
        assert data["level_previous"] == "L2"

    def test_annotations_before_json(self) -> None:
        v = _make_violation(location="CLAUDE.md:10")
        result = _make_result(violations=(v,))
        output = github_formatter.format_result(result)
        lines = output.strip().split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("::")
        # Last line is JSON
        json.loads(lines[1])
