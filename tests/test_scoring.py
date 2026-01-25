"""Scoring tests - scores must be reproducible and match spec.

The score (0-10) represents how well a project follows reporails rules.
Scoring must be deterministic and predictable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.models import Severity, Violation


class TestScoreCalculation:
    """Test score calculation from violations."""

    def test_no_violations_perfect_score(self) -> None:
        """No violations should result in perfect 10.0 score."""
        from reporails_cli.core.scorer import calculate_score

        score = calculate_score(rules_checked=10, violations=[])

        assert score == 10.0, (
            f"No violations should give 10.0, got {score}"
        )

    def test_violations_reduce_score(self) -> None:
        """Violations should reduce score from 10.0."""
        from reporails_cli.core.scorer import calculate_score

        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test Rule",
                location="test.md:1",
                message="Test violation",
                severity=Severity.MEDIUM,
                check_id="test-check",
            )
        ]

        score = calculate_score(rules_checked=10, violations=violations)

        assert score < 10.0, (
            f"Violations should reduce score below 10.0, got {score}"
        )
        assert score >= 0.0, (
            f"Score should not go below 0, got {score}"
        )

    def test_more_violations_lower_score(self) -> None:
        """More violations should result in lower score."""
        from reporails_cli.core.scorer import calculate_score

        one_violation = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.MEDIUM,
                check_id="test",
            )
        ]

        three_violations = [
            Violation(
                rule_id=f"S{i}",
                rule_title="Test",
                location=f"test.md:{i}",
                message="Test",
                severity=Severity.MEDIUM,
                check_id="test",
            )
            for i in range(3)
        ]

        score_one = calculate_score(rules_checked=10, violations=one_violation)
        score_three = calculate_score(rules_checked=10, violations=three_violations)

        assert score_three < score_one, (
            f"More violations should give lower score: "
            f"1 violation={score_one}, 3 violations={score_three}"
        )

    def test_higher_severity_more_impact(self) -> None:
        """Higher severity violations should impact score more."""
        from reporails_cli.core.scorer import calculate_score

        low_violation = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.LOW,
                check_id="test",
            )
        ]

        critical_violation = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.CRITICAL,
                check_id="test",
            )
        ]

        score_low = calculate_score(rules_checked=10, violations=low_violation)
        score_critical = calculate_score(rules_checked=10, violations=critical_violation)

        assert score_critical < score_low, (
            f"Critical violation should impact more than low: "
            f"LOW={score_low}, CRITICAL={score_critical}"
        )


class TestScoreDeterminism:
    """Test that scoring is deterministic."""

    def test_same_violations_same_score(self) -> None:
        """Same violations should always produce same score."""
        from reporails_cli.core.scorer import calculate_score

        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.MEDIUM,
                check_id="test",
            )
        ]

        scores = [
            calculate_score(rules_checked=10, violations=violations)
            for _ in range(5)
        ]

        assert len(set(scores)) == 1, (
            f"Same violations should give same score, got: {scores}"
        )

    def test_violation_order_does_not_affect_score(self) -> None:
        """Order of violations should not affect score."""
        from reporails_cli.core.scorer import calculate_score

        v1 = Violation(
            rule_id="S1",
            rule_title="Rule 1",
            location="a.md:1",
            message="Test",
            severity=Severity.HIGH,
            check_id="test",
        )
        v2 = Violation(
            rule_id="S2",
            rule_title="Rule 2",
            location="b.md:1",
            message="Test",
            severity=Severity.LOW,
            check_id="test",
        )

        score_12 = calculate_score(rules_checked=10, violations=[v1, v2])
        score_21 = calculate_score(rules_checked=10, violations=[v2, v1])

        assert score_12 == score_21, (
            f"Violation order should not matter: [v1,v2]={score_12}, [v2,v1]={score_21}"
        )


class TestValidationScoring:
    """Test scoring through validation pipeline."""

    def test_clean_project_high_score(self, level2_project: Path) -> None:
        """Clean project should have high score."""
        from reporails_cli.core.engine import run_validation_sync

        result = run_validation_sync(level2_project, agent="claude")

        # A clean project should score well
        assert result.score >= 8.0, (
            f"Clean project should score 8+, got {result.score}\n"
            f"Violations: {result.violations}"
        )

    def test_score_reproducible_across_runs(self, level3_project: Path) -> None:
        """Same project should produce same score across runs."""
        from reporails_cli.core.engine import run_validation_sync

        scores = []
        for _ in range(3):
            result = run_validation_sync(level3_project, agent="claude")
            scores.append(result.score)

        assert len(set(scores)) == 1, (
            f"Score should be reproducible, got: {scores}"
        )

    def test_score_is_deterministic_for_same_content(self, tmp_path: Path) -> None:
        """Same content should produce same score across runs."""
        from reporails_cli.core.engine import run_validation_sync

        # Create project with content
        (tmp_path / "CLAUDE.md").write_text("""\
# Test Project

A test project.

## Commands

- `test` - Run tests

## Architecture

Simple architecture.
""")

        result1 = run_validation_sync(tmp_path, agent="claude")
        result2 = run_validation_sync(tmp_path, agent="claude")

        # Same content should give same score
        assert result1.score == result2.score, (
            f"Same content gave different scores: {result1.score} vs {result2.score}"
        )


class TestViolationDeduplication:
    """Test that duplicate violations are handled correctly."""

    def test_duplicate_violations_deduped(self) -> None:
        """Duplicate violations should be deduplicated."""
        from reporails_cli.core.sarif import dedupe_violations

        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Same violation",
                severity=Severity.MEDIUM,
                check_id="test",
            ),
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:5",  # Same file, same rule
                message="Same violation",
                severity=Severity.MEDIUM,
                check_id="test",
            ),
        ]

        deduped = dedupe_violations(violations)

        # Should keep only one per (file, rule_id)
        assert len(deduped) == 1, (
            f"Should dedupe same rule in same file, got {len(deduped)}"
        )

    def test_different_files_not_deduped(self) -> None:
        """Same rule in different files should not be deduped."""
        from reporails_cli.core.sarif import dedupe_violations

        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="a.md:1",
                message="Violation",
                severity=Severity.MEDIUM,
                check_id="test",
            ),
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="b.md:1",  # Different file
                message="Violation",
                severity=Severity.MEDIUM,
                check_id="test",
            ),
        ]

        deduped = dedupe_violations(violations)

        # Different files should both be kept
        assert len(deduped) == 2, (
            f"Different files should not be deduped, got {len(deduped)}"
        )

    def test_different_rules_not_deduped(self) -> None:
        """Different rules in same file should not be deduped."""
        from reporails_cli.core.sarif import dedupe_violations

        violations = [
            Violation(
                rule_id="S1",
                rule_title="Rule 1",
                location="test.md:1",
                message="Violation 1",
                severity=Severity.MEDIUM,
                check_id="test1",
            ),
            Violation(
                rule_id="S2",  # Different rule
                rule_title="Rule 2",
                location="test.md:1",
                message="Violation 2",
                severity=Severity.MEDIUM,
                check_id="test2",
            ),
        ]

        deduped = dedupe_violations(violations)

        # Different rules should both be kept
        assert len(deduped) == 2, (
            f"Different rules should not be deduped, got {len(deduped)}"
        )


class TestScoreBounds:
    """Test that scores stay within valid bounds."""

    def test_score_minimum_zero(self) -> None:
        """Score should never go below 0."""
        from reporails_cli.core.scorer import calculate_score

        # Create many high-severity violations
        many_violations = [
            Violation(
                rule_id=f"S{i}",
                rule_title="Test",
                location=f"test{i}.md:1",
                message="Test",
                severity=Severity.CRITICAL,
                check_id="test",
            )
            for i in range(100)
        ]

        score = calculate_score(rules_checked=5, violations=many_violations)

        assert score >= 0.0, f"Score should not go below 0, got {score}"

    def test_score_maximum_ten(self) -> None:
        """Score should never exceed 10."""
        from reporails_cli.core.scorer import calculate_score

        score = calculate_score(rules_checked=100, violations=[])

        assert score <= 10.0, f"Score should not exceed 10, got {score}"

    def test_score_zero_rules_checked(self) -> None:
        """Zero rules checked should handle gracefully."""
        from reporails_cli.core.scorer import calculate_score

        # Should not crash
        score = calculate_score(rules_checked=0, violations=[])

        assert score >= 0.0, "Should return valid score even with 0 rules"
        assert score <= 10.0, "Should return valid score even with 0 rules"
