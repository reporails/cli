"""Tests for template system and CLI output formatting.

Tests cover:
- Template loading and rendering
- Partial vs complete evaluation display
- MCP CTA display
- Pending semantic rules display
"""

from __future__ import annotations

import pytest

from reporails_cli.core.models import (
    FrictionEstimate,
    Level,
    PendingSemantic,
    Severity,
    ValidationResult,
    Violation,
)


class TestTemplateLoader:
    """Test template loading functionality."""

    def test_load_existing_template(self) -> None:
        """Should load existing template files."""
        from reporails_cli.templates import load_template

        content = load_template("cli_legend.txt")
        assert "{crit}" in content
        assert "{high}" in content

    def test_load_missing_template_raises(self) -> None:
        """Should raise FileNotFoundError for missing templates."""
        from reporails_cli.templates import load_template

        with pytest.raises(FileNotFoundError, match="Template not found"):
            load_template("nonexistent.txt")

    def test_render_substitutes_variables(self) -> None:
        """Should substitute variables in template."""
        from reporails_cli.templates import render

        result = render("cli_legend.txt", crit="!", high="!", med="o", low="-")
        assert "!" in result
        assert "o" in result

    def test_render_missing_variable_raises(self) -> None:
        """Should raise KeyError for missing variables."""
        from reporails_cli.templates import render

        with pytest.raises(KeyError, match="Missing template variable"):
            render("cli_legend.txt", crit="!")  # Missing high, med, low

    def test_render_conditional_true(self) -> None:
        """Should render template when condition is true."""
        from reporails_cli.templates import render_conditional

        result = render_conditional("cli_legend.txt", True, crit="!", high="!", med="o", low="-")
        assert result != ""

    def test_render_conditional_false(self) -> None:
        """Should return empty when condition is false."""
        from reporails_cli.templates import render_conditional

        result = render_conditional("cli_legend.txt", False, crit="!", high="!", med="o", low="-")
        assert result == ""


class TestPartialEvaluation:
    """Test partial vs complete evaluation display."""

    def _make_result(
        self,
        is_partial: bool = True,
        pending_semantic: PendingSemantic | None = None,
        violations_count: int = 3,
    ) -> ValidationResult:
        """Create a ValidationResult for testing."""
        violations = tuple(
            Violation(
                rule_id=f"S{i}",
                rule_title="Test",
                location=f"test{i}.md:1",
                message="Test",
                severity=Severity.MEDIUM,
                check_id="test",
            )
            for i in range(violations_count)
        )
        return ValidationResult(
            score=7.5,
            level=Level.L3,
            violations=violations,
            judgment_requests=(),
            rules_checked=10,
            rules_passed=7,
            rules_failed=3,
            feature_summary="Root file",
            friction=FrictionEstimate(level="low", total_minutes=5, by_category={}),
            is_partial=is_partial,
            pending_semantic=pending_semantic,
        )

    def test_partial_shows_partial_marker(self) -> None:
        """Partial evaluation should show (partial) marker."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_result(is_partial=True)
        output = text_formatter.format_result(result)

        assert "(partial)" in output

    def test_complete_no_partial_marker(self) -> None:
        """Complete evaluation should not show (partial) marker."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_result(is_partial=False)
        output = text_formatter.format_result(result)

        # Should not contain (partial)
        assert "(partial)" not in output

    def test_json_includes_evaluation_field(self) -> None:
        """JSON output should include evaluation completeness field."""
        from reporails_cli.formatters import json as json_formatter

        result = self._make_result(is_partial=True)
        data = json_formatter.format_result(result)

        assert data["evaluation"] == "partial"
        assert data["is_partial"] is True

    def test_json_complete_evaluation(self) -> None:
        """JSON output should show complete when not partial."""
        from reporails_cli.formatters import json as json_formatter

        result = self._make_result(is_partial=False)
        data = json_formatter.format_result(result)

        assert data["evaluation"] == "complete"
        assert data["is_partial"] is False

    def test_compact_shows_partial(self) -> None:
        """Compact format should show partial marker."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_result(is_partial=True)
        output = text_formatter.format_compact(result)

        assert "(partial)" in output


class TestPendingSemanticDisplay:
    """Test pending semantic rules display."""

    def _make_result_with_pending(self) -> ValidationResult:
        """Create a result with pending semantic rules."""
        pending = PendingSemantic(
            rule_count=3,
            file_count=5,
            rules=("C6", "C10", "M4"),
        )
        return ValidationResult(
            score=7.5,
            level=Level.L3,
            violations=(),
            judgment_requests=(),
            rules_checked=10,
            rules_passed=10,
            rules_failed=0,
            feature_summary="Root file",
            friction=FrictionEstimate(level="none", total_minutes=0, by_category={}),
            is_partial=True,
            pending_semantic=pending,
        )

    def test_text_shows_pending_section(self) -> None:
        """Text output should show pending semantic section."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_result_with_pending()
        output = text_formatter.format_result(result, quiet_semantic=False)

        assert "Pending semantic evaluation:" in output
        assert "3 rules" in output
        assert "C6" in output

    def test_quiet_semantic_hides_pending(self) -> None:
        """Quiet semantic mode should hide pending section."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_result_with_pending()
        output = text_formatter.format_result(result, quiet_semantic=True)

        assert "Pending semantic evaluation:" not in output

    def test_json_includes_pending_semantic(self) -> None:
        """JSON output should include pending_semantic field."""
        from reporails_cli.formatters import json as json_formatter

        result = self._make_result_with_pending()
        data = json_formatter.format_result(result)

        assert data["pending_semantic"] is not None
        assert data["pending_semantic"]["rule_count"] == 3
        assert data["pending_semantic"]["file_count"] == 5
        assert "C6" in data["pending_semantic"]["rules"]

    def test_json_null_pending_when_complete(self) -> None:
        """JSON output should have null pending when complete."""
        from reporails_cli.formatters import json as json_formatter

        result = ValidationResult(
            score=10.0,
            level=Level.L3,
            violations=(),
            judgment_requests=(),
            rules_checked=10,
            rules_passed=10,
            rules_failed=0,
            feature_summary="Root file",
            friction=FrictionEstimate(level="none", total_minutes=0, by_category={}),
            is_partial=False,
            pending_semantic=None,
        )
        data = json_formatter.format_result(result)

        assert data["pending_semantic"] is None

    def test_compact_shows_pending_summary(self) -> None:
        """Compact format should show pending summary."""
        from reporails_cli.formatters import text as text_formatter

        # Create result with violations (compact returns early without violations)
        pending = PendingSemantic(
            rule_count=3,
            file_count=5,
            rules=("C6", "C10", "M4"),
        )
        result = ValidationResult(
            score=7.5,
            level=Level.L3,
            violations=(
                Violation(
                    rule_id="S1",
                    rule_title="Test",
                    location="test.md:1",
                    message="Test",
                    severity=Severity.MEDIUM,
                    check_id="test",
                ),
            ),
            judgment_requests=(),
            rules_checked=10,
            rules_passed=9,
            rules_failed=1,
            feature_summary="Root file",
            friction=FrictionEstimate(level="none", total_minutes=0, by_category={}),
            is_partial=True,
            pending_semantic=pending,
        )
        output = text_formatter.format_compact(result)

        assert "Pending:" in output
        assert "semantic rules" in output


class TestMCPCallToAction:
    """Test MCP call-to-action display."""

    def _make_partial_result(self) -> ValidationResult:
        """Create a partial result."""
        return ValidationResult(
            score=7.5,
            level=Level.L3,
            violations=(
                Violation(
                    rule_id="S1",
                    rule_title="Test",
                    location="test.md:1",
                    message="Test",
                    severity=Severity.MEDIUM,
                    check_id="test",
                ),
            ),
            judgment_requests=(),
            rules_checked=10,
            rules_passed=9,
            rules_failed=1,
            feature_summary="Root file",
            friction=FrictionEstimate(level="low", total_minutes=5, by_category={}),
            is_partial=True,
            pending_semantic=PendingSemantic(rule_count=2, file_count=1, rules=("C6", "C10")),
        )

    def test_cta_shown_when_partial(self) -> None:
        """CTA should be shown when evaluation is partial."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_partial_result()
        output = text_formatter.format_result(result, quiet_semantic=False)

        assert "For complete analysis" in output
        assert "claude mcp add" in output

    def test_cta_hidden_when_quiet_semantic(self) -> None:
        """CTA should be hidden in quiet semantic mode."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_partial_result()
        output = text_formatter.format_result(result, quiet_semantic=True)

        assert "For complete analysis" not in output

    def test_cta_hidden_when_complete(self) -> None:
        """CTA should be hidden when evaluation is complete."""
        from reporails_cli.formatters import text as text_formatter

        result = ValidationResult(
            score=10.0,
            level=Level.L3,
            violations=(),
            judgment_requests=(),
            rules_checked=10,
            rules_passed=10,
            rules_failed=0,
            feature_summary="Root file",
            friction=FrictionEstimate(level="none", total_minutes=0, by_category={}),
            is_partial=False,
            pending_semantic=None,
        )
        output = text_formatter.format_result(result)

        assert "For complete analysis" not in output


class TestFormatScore:
    """Test format_score function."""

    def test_partial_marker_in_score(self) -> None:
        """Score summary should show partial marker."""
        from reporails_cli.formatters import text as text_formatter

        result = ValidationResult(
            score=7.5,
            level=Level.L3,
            violations=(),
            judgment_requests=(),
            rules_checked=10,
            rules_passed=10,
            rules_failed=0,
            feature_summary="Root file",
            friction=FrictionEstimate(level="none", total_minutes=0, by_category={}),
            is_partial=True,
            pending_semantic=None,
        )
        output = text_formatter.format_score(result)

        assert "(partial)" in output

    def test_no_partial_marker_when_complete(self) -> None:
        """Score summary should not show partial marker when complete."""
        from reporails_cli.formatters import text as text_formatter

        result = ValidationResult(
            score=7.5,
            level=Level.L3,
            violations=(),
            judgment_requests=(),
            rules_checked=10,
            rules_passed=10,
            rules_failed=0,
            feature_summary="Root file",
            friction=FrictionEstimate(level="none", total_minutes=0, by_category={}),
            is_partial=False,
            pending_semantic=None,
        )
        output = text_formatter.format_score(result)

        assert "(partial)" not in output
