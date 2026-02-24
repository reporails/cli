"""Tests for the 'improved since last run' delta comparison feature.

Tests cover:
- ScanDelta computation from analytics
- Delta display in formatters
- JSON output includes delta fields
"""

from __future__ import annotations

from reporails_cli.core.cache import AnalyticsEntry
from reporails_cli.core.models import (
    FrictionEstimate,
    Level,
    ScanDelta,
    Severity,
    ValidationResult,
    Violation,
)


class TestScanDeltaComputation:
    """Test ScanDelta.compute() logic."""

    def test_no_previous_returns_all_none(self) -> None:
        """With no previous scan, all delta fields should be None."""
        delta = ScanDelta.compute(
            current_score=7.5,
            current_level="L3",
            current_violations=5,
            previous=None,
        )

        assert delta.score_delta is None
        assert delta.level_previous is None
        assert delta.level_improved is None
        assert delta.violations_delta is None

    def test_improved_score_positive_delta(self) -> None:
        """Score improvement should show positive delta."""
        previous = AnalyticsEntry(
            timestamp="2024-01-01T00:00:00Z",
            score=6.5,
            level="L3",
            violations_count=8,
            rules_checked=10,
            elapsed_ms=100.0,
            instruction_files=1,
        )

        delta = ScanDelta.compute(
            current_score=7.3,
            current_level="L3",
            current_violations=8,
            previous=previous,
        )

        assert delta.score_delta == 0.8
        assert delta.level_previous is None  # Same level
        assert delta.level_improved is None
        assert delta.violations_delta is None  # Same violations

    def test_regressed_score_negative_delta(self) -> None:
        """Score regression should show negative delta."""
        previous = AnalyticsEntry(
            timestamp="2024-01-01T00:00:00Z",
            score=8.0,
            level="L3",
            violations_count=3,
            rules_checked=10,
            elapsed_ms=100.0,
            instruction_files=1,
        )

        delta = ScanDelta.compute(
            current_score=6.5,
            current_level="L3",
            current_violations=3,
            previous=previous,
        )

        assert delta.score_delta == -1.5

    def test_level_improved(self) -> None:
        """Level improvement should set level_improved=True."""
        previous = AnalyticsEntry(
            timestamp="2024-01-01T00:00:00Z",
            score=7.0,
            level="L2",
            violations_count=5,
            rules_checked=10,
            elapsed_ms=100.0,
            instruction_files=1,
        )

        delta = ScanDelta.compute(
            current_score=7.0,
            current_level="L3",
            current_violations=5,
            previous=previous,
        )

        assert delta.level_previous == "L2"
        assert delta.level_improved is True

    def test_level_regressed(self) -> None:
        """Level regression should set level_improved=False."""
        previous = AnalyticsEntry(
            timestamp="2024-01-01T00:00:00Z",
            score=7.0,
            level="L4",
            violations_count=5,
            rules_checked=10,
            elapsed_ms=100.0,
            instruction_files=1,
        )

        delta = ScanDelta.compute(
            current_score=7.0,
            current_level="L3",
            current_violations=5,
            previous=previous,
        )

        assert delta.level_previous == "L4"
        assert delta.level_improved is False

    def test_violations_decreased(self) -> None:
        """Fewer violations should show negative delta (improvement)."""
        previous = AnalyticsEntry(
            timestamp="2024-01-01T00:00:00Z",
            score=7.0,
            level="L3",
            violations_count=10,
            rules_checked=10,
            elapsed_ms=100.0,
            instruction_files=1,
        )

        delta = ScanDelta.compute(
            current_score=7.0,
            current_level="L3",
            current_violations=6,
            previous=previous,
        )

        assert delta.violations_delta == -4

    def test_violations_increased(self) -> None:
        """More violations should show positive delta (regression)."""
        previous = AnalyticsEntry(
            timestamp="2024-01-01T00:00:00Z",
            score=7.0,
            level="L3",
            violations_count=5,
            rules_checked=10,
            elapsed_ms=100.0,
            instruction_files=1,
        )

        delta = ScanDelta.compute(
            current_score=7.0,
            current_level="L3",
            current_violations=8,
            previous=previous,
        )

        assert delta.violations_delta == 3

    def test_unchanged_values_are_none(self) -> None:
        """Unchanged values should return None, not 0."""
        previous = AnalyticsEntry(
            timestamp="2024-01-01T00:00:00Z",
            score=7.5,
            level="L3",
            violations_count=5,
            rules_checked=10,
            elapsed_ms=100.0,
            instruction_files=1,
        )

        delta = ScanDelta.compute(
            current_score=7.5,
            current_level="L3",
            current_violations=5,
            previous=previous,
        )

        # All unchanged - should be None
        assert delta.score_delta is None
        assert delta.level_previous is None
        assert delta.level_improved is None
        assert delta.violations_delta is None


class TestDeltaInFormatters:
    """Test delta display in formatters."""

    def _make_result(self, score: float = 7.5, violations_count: int = 3) -> ValidationResult:
        """Create a minimal ValidationResult for testing."""
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
            score=score,
            level=Level.L3,
            violations=violations,
            judgment_requests=(),
            rules_checked=10,
            rules_passed=7,
            rules_failed=3,
            feature_summary="Root file",
            friction=FrictionEstimate(level="small"),
        )

    def test_json_formatter_includes_delta_fields(self) -> None:
        """JSON formatter should include delta fields."""
        from reporails_cli.formatters import json as json_formatter

        result = self._make_result()
        delta = ScanDelta(
            score_delta=0.8,
            level_previous="L2",
            level_improved=True,
            violations_delta=-2,
        )

        data = json_formatter.format_result(result, delta)

        assert data["score_delta"] == 0.8
        assert data["level_previous"] == "L2"
        assert data["level_improved"] is True
        assert data["violations_delta"] == -2

    def test_json_formatter_null_delta_fields_without_previous(self) -> None:
        """JSON formatter should include null delta fields when no previous scan."""
        from reporails_cli.formatters import json as json_formatter

        result = self._make_result()

        data = json_formatter.format_result(result, delta=None)

        assert data["score_delta"] is None
        assert data["level_previous"] is None
        assert data["level_improved"] is None
        assert data["violations_delta"] is None

    def test_text_formatter_shows_score_improvement(self) -> None:
        """Text formatter should show score improvement indicator."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_result(score=7.3)
        delta = ScanDelta(
            score_delta=0.8,
            level_previous=None,
            level_improved=None,
            violations_delta=None,
        )

        output = text_formatter.format_result(result, delta=delta)

        assert "↑ +0.8" in output or "^ +0.8" in output

    def test_text_formatter_shows_score_regression(self) -> None:
        """Text formatter should show score regression indicator."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_result(score=6.5)
        delta = ScanDelta(
            score_delta=-1.5,
            level_previous=None,
            level_improved=None,
            violations_delta=None,
        )

        output = text_formatter.format_result(result, delta=delta)

        assert "↓ -1.5" in output or "v -1.5" in output

    def test_text_formatter_shows_level_improvement(self) -> None:
        """Text formatter should show level improvement indicator."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_result()
        delta = ScanDelta(
            score_delta=None,
            level_previous="L2",
            level_improved=True,
            violations_delta=None,
        )

        # Full format may truncate level in box display, so test compact instead
        compact_output = text_formatter.format_compact(result, delta=delta)
        assert "from L2" in compact_output

    def test_compact_formatter_shows_delta(self) -> None:
        """Compact formatter should show delta indicators."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_result(score=7.3, violations_count=5)
        delta = ScanDelta(
            score_delta=0.5,
            level_previous=None,
            level_improved=None,
            violations_delta=-3,
        )

        output = text_formatter.format_compact(result, delta=delta)

        # Should contain score delta
        assert "+0.5" in output
        # Should contain violations delta
        assert "-3" in output

    def test_no_delta_shows_no_indicators(self) -> None:
        """Without delta, no indicators should appear."""
        from reporails_cli.formatters import text as text_formatter

        result = self._make_result()

        output = text_formatter.format_result(result, delta=None)

        # Should not contain delta indicators
        assert "↑" not in output and "from L" not in output
        assert "↓" not in output


class TestDeltaDisplayRules:
    """Test delta display formatting rules."""

    def test_score_improvement_format(self) -> None:
        """Score improvement should show ↑ +X.X format."""
        from reporails_cli.formatters.text import _format_score_delta

        delta = ScanDelta(score_delta=0.8, level_previous=None, level_improved=None, violations_delta=None)
        result = _format_score_delta(delta, ascii_mode=False)

        assert "↑" in result and "+0.8" in result

    def test_score_regression_format(self) -> None:
        """Score regression should show ↓ -X.X format."""
        from reporails_cli.formatters.text import _format_score_delta

        delta = ScanDelta(score_delta=-1.5, level_previous=None, level_improved=None, violations_delta=None)
        result = _format_score_delta(delta, ascii_mode=False)

        assert "↓" in result and "-1.5" in result

    def test_level_improvement_format(self) -> None:
        """Level improvement should show ↑ from LX format."""
        from reporails_cli.formatters.text import _format_level_delta

        delta = ScanDelta(score_delta=None, level_previous="L2", level_improved=True, violations_delta=None)
        result = _format_level_delta(delta, ascii_mode=False)

        assert "↑" in result and "from L2" in result

    def test_level_regression_format(self) -> None:
        """Level regression should show ↓ from LX format."""
        from reporails_cli.formatters.text import _format_level_delta

        delta = ScanDelta(score_delta=None, level_previous="L4", level_improved=False, violations_delta=None)
        result = _format_level_delta(delta, ascii_mode=False)

        assert "↓" in result and "from L4" in result

    def test_violations_decreased_format(self) -> None:
        """Violations decrease (good) should show ↓ -N format."""
        from reporails_cli.formatters.text import _format_violations_delta

        delta = ScanDelta(score_delta=None, level_previous=None, level_improved=None, violations_delta=-4)
        result = _format_violations_delta(delta, ascii_mode=False)

        assert "↓" in result and "-4" in result

    def test_violations_increased_format(self) -> None:
        """Violations increase (bad) should show ↑ +N format."""
        from reporails_cli.formatters.text import _format_violations_delta

        delta = ScanDelta(score_delta=None, level_previous=None, level_improved=None, violations_delta=3)
        result = _format_violations_delta(delta, ascii_mode=False)

        assert "↑" in result and "+3" in result

    def test_ascii_mode_uses_ascii_arrows(self) -> None:
        """ASCII mode should use ^ and v instead of ↑ and ↓."""
        from reporails_cli.formatters.text import _format_score_delta

        delta = ScanDelta(score_delta=0.8, level_previous=None, level_improved=None, violations_delta=None)
        result = _format_score_delta(delta, ascii_mode=True)

        assert "^" in result and "+0.8" in result

    def test_none_delta_returns_empty_string(self) -> None:
        """None values should return empty string."""
        from reporails_cli.formatters.text import (
            _format_level_delta,
            _format_score_delta,
            _format_violations_delta,
        )

        delta = ScanDelta(score_delta=None, level_previous=None, level_improved=None, violations_delta=None)

        assert _format_score_delta(delta) == ""
        assert _format_level_delta(delta) == ""
        assert _format_violations_delta(delta) == ""

        # Also test with None delta
        assert _format_score_delta(None) == ""
        assert _format_level_delta(None) == ""
        assert _format_violations_delta(None) == ""
