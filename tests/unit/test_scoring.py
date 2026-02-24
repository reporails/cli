"""Scoring unit tests - scores must be reproducible and match spec.

The score (0-10) represents how well a project follows reporails rules.
Scoring must be deterministic and predictable.

These tests are pure unit tests with no external dependencies.
"""

from __future__ import annotations

from reporails_cli.core.models import Severity, Violation


class TestScoreCalculation:
    """Test score calculation from violations."""

    def test_no_violations_perfect_score(self) -> None:
        """No violations should result in perfect 10.0 score."""
        from reporails_cli.core.scorer import calculate_score

        score = calculate_score(rules_checked=10, violations=[])

        assert score == 10.0, f"No violations should give 10.0, got {score}"

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

        assert score < 10.0, f"Violations should reduce score below 10.0, got {score}"
        assert score >= 0.0, f"Score should not go below 0, got {score}"

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
            f"More violations should give lower score: 1 violation={score_one}, 3 violations={score_three}"
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
            f"Critical violation should impact more than low: LOW={score_low}, CRITICAL={score_critical}"
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

        scores = [calculate_score(rules_checked=10, violations=violations) for _ in range(5)]

        assert len(set(scores)) == 1, f"Same violations should give same score, got: {scores}"

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

        assert score_12 == score_21, f"Violation order should not matter: [v1,v2]={score_12}, [v2,v1]={score_21}"


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
        """Zero rules checked should return perfect score (no rules = nothing failed)."""
        from reporails_cli.core.scorer import calculate_score

        score = calculate_score(rules_checked=0, violations=[])

        assert score == 10.0


class TestScoreAnchored:
    """Anchored score values — catch formula regressions."""

    def test_single_medium_violation_anchored(self) -> None:
        """One MEDIUM violation out of 10 rules: lost 2.5, earned 22.5/25 = 9.0."""
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

        score = calculate_score(rules_checked=10, violations=violations)
        assert score == 9.0, f"Expected 9.0, got {score}"

    def test_single_critical_violation_anchored(self) -> None:
        """One CRITICAL violation out of 10 rules: capped at 2.5, earned 22.5/25 = 9.0."""
        from reporails_cli.core.scorer import calculate_score

        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.CRITICAL,
                check_id="test",
            )
        ]

        score = calculate_score(rules_checked=10, violations=violations)
        assert score == 9.0, f"Expected 9.0 (capped at rule weight), got {score}"

    def test_per_rule_cap_limits_deduction(self) -> None:
        """Multiple violations of the same rule should not deduct more than DEFAULT_RULE_WEIGHT."""
        from reporails_cli.core.scorer import calculate_score

        # 3 MEDIUM violations (3 * 2.5 = 7.5) for one rule — capped at 2.5
        same_rule_violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location=f"test.md:{i}",
                message="Test",
                severity=Severity.MEDIUM,
                check_id="test",
            )
            for i in range(3)
        ]

        # 1 violation of a different rule
        different_rule_violation = [
            Violation(
                rule_id="S2",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.MEDIUM,
                check_id="test",
            )
        ]

        score_same = calculate_score(rules_checked=10, violations=same_rule_violations)
        score_diff = calculate_score(rules_checked=10, violations=different_rule_violation)

        # Same rule 3x should be capped at 2.5 total, same as 1 violation of 1 rule
        assert score_same == score_diff, (
            f"Per-rule cap: 3 violations of 1 rule ({score_same}) should equal 1 violation ({score_diff})"
        )

    def test_different_rules_deduct_independently(self) -> None:
        """Violations of different rules should deduct independently."""
        from reporails_cli.core.scorer import calculate_score

        # 1 violation of 1 rule
        one_rule = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.MEDIUM,
                check_id="test",
            )
        ]

        # 1 violation of each of 2 different rules
        two_rules = [
            Violation(
                rule_id=f"S{i}",
                rule_title="Test",
                location=f"test.md:{i}",
                message="Test",
                severity=Severity.MEDIUM,
                check_id="test",
            )
            for i in range(2)
        ]

        score_one = calculate_score(rules_checked=10, violations=one_rule)
        score_two = calculate_score(rules_checked=10, violations=two_rules)

        assert score_two < score_one, "2 rules violated should score lower than 1 rule violated"
        assert score_one == 9.0, f"1 MEDIUM violation out of 10 rules: expected 9.0, got {score_one}"
        assert score_two == 8.0, f"2 MEDIUM violations out of 10 rules: expected 8.0, got {score_two}"


class TestEstimateFriction:
    """Test friction estimation from violations."""

    def test_no_violations_none(self) -> None:
        from reporails_cli.core.scorer import estimate_friction

        result = estimate_friction([])
        assert result.level == "none"

    def test_critical_extreme(self) -> None:
        from reporails_cli.core.scorer import estimate_friction

        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.CRITICAL,
                check_id="test",
            )
        ]
        result = estimate_friction(violations)
        assert result.level == "extreme"

    def test_two_high_is_high(self) -> None:
        from reporails_cli.core.scorer import estimate_friction

        violations = [
            Violation(
                rule_id=f"S{i}",
                rule_title="Test",
                location=f"test.md:{i}",
                message="Test",
                severity=Severity.HIGH,
                check_id="test",
            )
            for i in range(2)
        ]
        result = estimate_friction(violations)
        assert result.level == "high"

    def test_one_high_is_medium(self) -> None:
        from reporails_cli.core.scorer import estimate_friction

        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.HIGH,
                check_id="test",
            )
        ]
        result = estimate_friction(violations)
        assert result.level == "medium"

    def test_five_low_is_high(self) -> None:
        from reporails_cli.core.scorer import estimate_friction

        violations = [
            Violation(
                rule_id=f"S{i}",
                rule_title="Test",
                location=f"test.md:{i}",
                message="Test",
                severity=Severity.LOW,
                check_id="test",
            )
            for i in range(5)
        ]
        result = estimate_friction(violations)
        assert result.level == "high"

    def test_two_low_is_small(self) -> None:
        from reporails_cli.core.scorer import estimate_friction

        violations = [
            Violation(
                rule_id=f"S{i}",
                rule_title="Test",
                location=f"test.md:{i}",
                message="Test",
                severity=Severity.LOW,
                check_id="test",
            )
            for i in range(2)
        ]
        result = estimate_friction(violations)
        assert result.level == "small"


class TestHasCriticalViolations:
    """Test has_critical_violations."""

    def test_empty_list(self) -> None:
        from reporails_cli.core.scorer import has_critical_violations

        assert has_critical_violations([]) is False

    def test_no_critical(self) -> None:
        from reporails_cli.core.scorer import has_critical_violations

        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.HIGH,
                check_id="test",
            )
        ]
        assert has_critical_violations(violations) is False

    def test_has_critical(self) -> None:
        from reporails_cli.core.scorer import has_critical_violations

        violations = [
            Violation(
                rule_id="S1",
                rule_title="Test",
                location="test.md:1",
                message="Test",
                severity=Severity.CRITICAL,
                check_id="test",
            )
        ]
        assert has_critical_violations(violations) is True
