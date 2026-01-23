"""Unit tests for formatters module."""

from __future__ import annotations

import json

from reporails_cli.core.models import (
    JudgmentRequest,
    Level,
    Severity,
    ValidationResult,
    Violation,
)
from reporails_cli.formatters import mcp as mcp_formatter
from reporails_cli.formatters import text as text_formatter


def make_result(
    score: float = 8.0,
    level: Level = Level.L5,
    violations: tuple = (),
    judgment_requests: tuple = (),
    feature_summary: str = "1 instruction file",
    violation_points: int = -20,
) -> ValidationResult:
    """Helper to create test validation results."""
    return ValidationResult(
        score=score,
        level=level,
        violations=violations,
        judgment_requests=judgment_requests,
        rules_checked=10,
        rules_passed=8,
        rules_failed=2,
        time_waste_estimate={"total": 30, "S": 15, "C": 15},
        feature_summary=feature_summary,
        violation_points=violation_points,
    )


def make_violation(
    rule_id: str = "S1",
    severity: Severity = Severity.MEDIUM,
    location: str = "CLAUDE.md:42",
) -> Violation:
    """Helper to create test violations."""
    return Violation(
        rule_id=rule_id,
        rule_title="Test Rule",
        location=location,
        message="Test violation message",
        severity=severity,
        points=-10,
    )


class TestFormatMcp:
    """Test MCP JSON formatter."""

    def test_formats_basic_result(self) -> None:
        """Formats result with all required fields."""
        result = make_result()
        output = mcp_formatter.format_result(result)

        assert output["score"] == 8.0
        assert output["level"] == "L5"
        assert output["capability"] == "Governed"
        assert "summary" in output
        assert output["summary"]["rules_checked"] == 10

    def test_includes_friction(self) -> None:
        """Includes friction estimate."""
        result = make_result()
        output = mcp_formatter.format_result(result)

        assert "friction" in output
        assert output["friction"]["level"] == "high"
        assert output["friction"]["estimated_minutes"] == 30

    def test_formats_violations(self) -> None:
        """Formats violations list."""
        v = make_violation()
        result = make_result(violations=(v,))
        output = mcp_formatter.format_result(result)

        assert len(output["violations"]) == 1
        assert output["violations"][0]["rule_id"] == "S1"
        assert output["violations"][0]["location"] == "CLAUDE.md:42"
        assert output["violations"][0]["severity"] == "medium"

    def test_formats_judgment_requests(self) -> None:
        """Formats judgment requests list."""
        jr = JudgmentRequest(
            rule_id="C8",
            rule_title="Philosophy",
            content="content",
            location="CLAUDE.md",
            question="Is it clear?",
            criteria={"test": "value"},
            examples={"good": []},
            choices=["yes", "no"],
            pass_value="yes",
            severity=Severity.HIGH,
            points_if_fail=-15,
        )
        result = make_result(judgment_requests=(jr,))
        output = mcp_formatter.format_result(result)

        assert len(output["judgment_requests"]) == 1
        assert output["judgment_requests"][0]["rule_id"] == "C8"

    def test_output_is_json_serializable(self) -> None:
        """Output can be serialized to JSON."""
        result = make_result()
        output = mcp_formatter.format_result(result)
        # Should not raise
        json.dumps(output)


class TestFormatScoreMcp:
    """Test MCP score formatter."""

    def test_formats_score_summary(self) -> None:
        """Formats minimal score info."""
        result = make_result(score=8.5)
        output = mcp_formatter.format_score(result)

        assert output["score"] == 8.5
        assert output["capability"] == "Governed"
        assert output["rules_checked"] == 10
        assert "feature_summary" in output

    def test_includes_violation_count(self) -> None:
        """Includes violation count."""
        v = make_violation()
        result = make_result(violations=(v,))
        output = mcp_formatter.format_score(result)

        assert output["violations_count"] == 1

    def test_indicates_critical_violations(self) -> None:
        """Indicates presence of critical violations."""
        v = make_violation(severity=Severity.CRITICAL)
        result = make_result(violations=(v,))
        output = mcp_formatter.format_score(result)

        assert output["has_critical"] is True

    def test_includes_friction_level(self) -> None:
        """Includes friction level."""
        result = make_result()
        output = mcp_formatter.format_score(result)

        assert output["friction"] == "high"


class TestFormatText:
    """Test terminal text formatter.

    Text formatter takes ValidationResult directly.
    """

    def test_includes_score(self) -> None:
        """Output includes score on 0-10 scale."""
        result = make_result(score=7.5, level=Level.L4)
        output = text_formatter.format_result(result)

        assert "7.5" in output
        assert "/ 10" in output

    def test_includes_level(self) -> None:
        """Output includes capability level."""
        result = make_result(score=8.5, level=Level.L5)
        output = text_formatter.format_result(result)

        assert "CAPABILITY:" in output
        assert "Governed" in output  # L5 label

    def test_includes_setup_info(self) -> None:
        """Output includes setup/feature summary."""
        result = make_result(feature_summary="1 instruction file, .claude/rules/")
        output = text_formatter.format_result(result)

        assert "Setup:" in output
        assert "instruction file" in output

    def test_lists_violations(self) -> None:
        """Output lists violations with severity markers."""
        v = make_violation(rule_id="S1", severity=Severity.HIGH)
        result = make_result(violations=(v,))
        output = text_formatter.format_result(result)

        assert "S1" in output
        assert "HIGH" in output

    def test_no_violations_message(self) -> None:
        """Shows message when no violations."""
        result = make_result(violations=())
        output = text_formatter.format_result(result)

        assert "No violations found" in output

    def test_includes_friction_when_significant(self) -> None:
        """Shows friction estimate when >= 5 minutes."""
        result = make_result()
        output = text_formatter.format_result(result)

        assert "Friction:" in output
        assert "redo loops" in output
