"""Unit tests for scorer module - all pure functions."""

from __future__ import annotations

from reporails_cli.core.applicability import DetectedFeatures
from reporails_cli.core.models import Level, Severity, Violation
from reporails_cli.core.scorer import (
    SEVERITY_POINTS,
    calculate_score,
    determine_capability_level,
    estimate_time_waste,
    get_severity_points,
    has_critical_violations,
)


def make_violation(
    rule_id: str = "S1",
    severity: Severity = Severity.MEDIUM,
    points: int | None = None,
    location: str = "CLAUDE.md:1",
) -> Violation:
    """Helper to create test violations."""
    if points is None:
        points = SEVERITY_POINTS[severity]
    return Violation(
        rule_id=rule_id,
        rule_title="Test Rule",
        location=location,
        message="Test message",
        severity=severity,
        points=points,
    )


class TestSeverityPoints:
    """Test SEVERITY_POINTS constant."""

    def test_critical_is_minus_25(self) -> None:
        """Critical severity deducts 25 points."""
        assert SEVERITY_POINTS[Severity.CRITICAL] == -25

    def test_high_is_minus_15(self) -> None:
        """High severity deducts 15 points."""
        assert SEVERITY_POINTS[Severity.HIGH] == -15

    def test_medium_is_minus_10(self) -> None:
        """Medium severity deducts 10 points."""
        assert SEVERITY_POINTS[Severity.MEDIUM] == -10

    def test_low_is_minus_5(self) -> None:
        """Low severity deducts 5 points."""
        assert SEVERITY_POINTS[Severity.LOW] == -5


class TestCalculateScore:
    """Test calculate_score function.

    Score = (earned / possible) * 10
    - possible = rules_checked * 2.5 (default weight)
    - earned = possible - sum(violation_weights)
    - Weights: critical=5.5, high=4.0, medium=2.5, low=1.0
    """

    def test_no_violations_returns_10(self) -> None:
        """Score is 10.0 with no violations."""
        assert calculate_score(10, []) == 10.0

    def test_no_rules_returns_10(self) -> None:
        """Score is 10.0 with no rules checked."""
        assert calculate_score(0, []) == 10.0

    def test_single_critical_violation(self) -> None:
        """Single critical violation (weight 5.5) reduces score."""
        # 10 rules * 2.5 = 25 possible
        # 1 critical = 5.5 lost
        # earned = 19.5, score = 19.5/25 * 10 = 7.8
        violations = [make_violation(severity=Severity.CRITICAL)]
        assert calculate_score(10, violations) == 7.8

    def test_single_high_violation(self) -> None:
        """Single high violation (weight 4.0) reduces score."""
        # 10 rules * 2.5 = 25 possible
        # 1 high = 4.0 lost
        # earned = 21.0, score = 21.0/25 * 10 = 8.4
        violations = [make_violation(severity=Severity.HIGH)]
        assert calculate_score(10, violations) == 8.4

    def test_single_medium_violation(self) -> None:
        """Single medium violation (weight 2.5) reduces score."""
        # 10 rules * 2.5 = 25 possible
        # 1 medium = 2.5 lost
        # earned = 22.5, score = 22.5/25 * 10 = 9.0
        violations = [make_violation(severity=Severity.MEDIUM)]
        assert calculate_score(10, violations) == 9.0

    def test_single_low_violation(self) -> None:
        """Single low violation (weight 1.0) reduces score minimally."""
        # 10 rules * 2.5 = 25 possible
        # 1 low = 1.0 lost
        # earned = 24.0, score = 24.0/25 * 10 = 9.6
        violations = [make_violation(severity=Severity.LOW)]
        assert calculate_score(10, violations) == 9.6

    def test_multiple_violations(self) -> None:
        """Multiple violations are summed by weight."""
        # 10 rules * 2.5 = 25 possible
        # 1 critical (5.5) + 1 high (4.0) = 9.5 lost
        # earned = 15.5, score = 15.5/25 * 10 = 6.2
        violations = [
            make_violation(rule_id="S1", severity=Severity.CRITICAL, location="CLAUDE.md:1"),
            make_violation(rule_id="C1", severity=Severity.HIGH, location="CLAUDE.md:2"),
        ]
        assert calculate_score(10, violations) == 6.2

    def test_score_floors_at_zero(self) -> None:
        """Score cannot go below 0.0."""
        # 5 rules * 2.5 = 12.5 possible
        # 5 critical violations = 5 * 5.5 = 27.5 lost (> possible)
        # earned = 0 (floored), score = 0.0
        rules = ["S1", "S2", "S3", "C1", "C2"]
        violations = [
            make_violation(rule_id=rule_id, severity=Severity.CRITICAL, location=f"CLAUDE.md:{i}")
            for i, rule_id in enumerate(rules)
        ]
        assert calculate_score(5, violations) == 0.0

    def test_deduplication_by_file_rule(self) -> None:
        """Same rule in same file only counted once."""
        # 10 rules * 2.5 = 25 possible
        # 1 medium (deduplicated) = 2.5 lost
        # earned = 22.5, score = 9.0
        violations = [
            make_violation(rule_id="S1", severity=Severity.MEDIUM, location="CLAUDE.md:1"),
            make_violation(rule_id="S1", severity=Severity.MEDIUM, location="CLAUDE.md:5"),
        ]
        assert calculate_score(10, violations) == 9.0

    def test_same_rule_different_files_counted_separately(self) -> None:
        """Same rule in different files counted separately."""
        # 10 rules * 2.5 = 25 possible
        # 2 medium violations = 2 * 2.5 = 5.0 lost
        # earned = 20.0, score = 8.0
        violations = [
            make_violation(rule_id="S1", severity=Severity.MEDIUM, location="CLAUDE.md:1"),
            make_violation(rule_id="S1", severity=Severity.MEDIUM, location="other/CLAUDE.md:1"),
        ]
        assert calculate_score(10, violations) == 8.0

    def test_more_rules_dilutes_violation_impact(self) -> None:
        """More rules checked means each violation has less relative impact."""
        # 1 critical violation with 10 rules: score = 7.8
        # 1 critical violation with 20 rules: score = 8.9
        violations = [make_violation(severity=Severity.CRITICAL)]
        assert calculate_score(10, violations) == 7.8
        assert calculate_score(20, violations) == 8.9


class TestHasCriticalViolations:
    """Test has_critical_violations function."""

    def test_no_violations_returns_false(self) -> None:
        """No violations means no critical violations."""
        assert has_critical_violations([]) is False

    def test_only_low_violations_returns_false(self) -> None:
        """Low severity violations are not critical."""
        violations = [make_violation(severity=Severity.LOW)]
        assert has_critical_violations(violations) is False

    def test_critical_violation_returns_true(self) -> None:
        """Returns true when critical violation exists."""
        violations = [make_violation(severity=Severity.CRITICAL)]
        assert has_critical_violations(violations) is True

    def test_mixed_with_critical_returns_true(self) -> None:
        """Returns true when any violation is critical."""
        violations = [
            make_violation(severity=Severity.LOW, location="CLAUDE.md:1"),
            make_violation(severity=Severity.CRITICAL, location="CLAUDE.md:2"),
            make_violation(severity=Severity.MEDIUM, location="CLAUDE.md:3"),
        ]
        assert has_critical_violations(violations) is True


class TestDetermineCapabilityLevel:
    """Test determine_capability_level function.

    Capability level is determined purely by features, not score.
    """

    def test_none_features_returns_l1(self) -> None:
        """None features defaults to L1."""
        assert determine_capability_level(None) == Level.L1

    def test_no_claude_md_is_l1(self) -> None:
        """No CLAUDE.md means L1."""
        features = DetectedFeatures(has_claude_md=False)
        assert determine_capability_level(features) == Level.L1

    def test_only_claude_md_is_l2(self) -> None:
        """Only CLAUDE.md without imports/structure is L2."""
        features = DetectedFeatures(has_claude_md=True)
        assert determine_capability_level(features) == Level.L2

    def test_imports_is_l3(self) -> None:
        """Has imports but no .claude/rules/ is L3."""
        features = DetectedFeatures(has_claude_md=True, has_imports=True)
        assert determine_capability_level(features) == Level.L3

    def test_multiple_files_is_l3(self) -> None:
        """Multiple instruction files is L3."""
        features = DetectedFeatures(has_claude_md=True, has_multiple_instruction_files=True)
        assert determine_capability_level(features) == Level.L3

    def test_rules_dir_is_l4(self) -> None:
        """Has .claude/rules/ is L4."""
        features = DetectedFeatures(has_claude_md=True, has_rules_dir=True)
        assert determine_capability_level(features) == Level.L4

    def test_many_components_is_l5(self) -> None:
        """3+ components is L5."""
        features = DetectedFeatures(has_claude_md=True, has_rules_dir=True, component_count=3)
        assert determine_capability_level(features) == Level.L5

    def test_shared_files_is_l5(self) -> None:
        """Shared files is L5."""
        features = DetectedFeatures(has_claude_md=True, has_rules_dir=True, has_shared_files=True)
        assert determine_capability_level(features) == Level.L5

    def test_backbone_is_l6(self) -> None:
        """Has backbone is L6."""
        features = DetectedFeatures(has_claude_md=True, has_backbone=True)
        assert determine_capability_level(features) == Level.L6

    def test_backbone_takes_precedence(self) -> None:
        """Backbone overrides other features (highest capability)."""
        features = DetectedFeatures(
            has_claude_md=True,
            has_rules_dir=True,
            has_backbone=True,
            component_count=5,
        )
        assert determine_capability_level(features) == Level.L6


class TestEstimateTimeWaste:
    """Test estimate_time_waste function.

    Time waste is based on severity, not individual rules:
    - Critical: 5 min
    - High: 3 min
    - Medium: 2 min
    - Low: 1 min
    """

    def test_no_violations_returns_zero_total(self) -> None:
        """No violations means no time waste."""
        result = estimate_time_waste([])
        assert result["total"] == 0

    def test_critical_severity_is_5_minutes(self) -> None:
        """Critical severity = 5 minutes."""
        violations = [make_violation(severity=Severity.CRITICAL)]
        result = estimate_time_waste(violations)
        assert result["total"] == 5

    def test_high_severity_is_3_minutes(self) -> None:
        """High severity = 3 minutes."""
        violations = [make_violation(severity=Severity.HIGH)]
        result = estimate_time_waste(violations)
        assert result["total"] == 3

    def test_medium_severity_is_2_minutes(self) -> None:
        """Medium severity = 2 minutes."""
        violations = [make_violation(severity=Severity.MEDIUM)]
        result = estimate_time_waste(violations)
        assert result["total"] == 2

    def test_low_severity_is_1_minute(self) -> None:
        """Low severity = 1 minute."""
        violations = [make_violation(severity=Severity.LOW)]
        result = estimate_time_waste(violations)
        assert result["total"] == 1

    def test_groups_by_category(self) -> None:
        """Time is grouped by rule category."""
        violations = [
            make_violation(rule_id="S1", location="CLAUDE.md:1"),  # Structure
            make_violation(rule_id="C2", location="CLAUDE.md:2"),  # Content
        ]
        result = estimate_time_waste(violations)
        assert "S" in result
        assert "C" in result

    def test_sums_multiple_violations(self) -> None:
        """Multiple violations in same category are summed."""
        violations = [
            make_violation(rule_id="S1", severity=Severity.CRITICAL, location="CLAUDE.md:1"),
            make_violation(rule_id="S2", severity=Severity.HIGH, location="CLAUDE.md:2"),
        ]
        result = estimate_time_waste(violations)
        assert result["S"] == 8  # 5 + 3

    def test_deduplication_same_rule_same_file(self) -> None:
        """Same rule in same file only counted once for time waste."""
        violations = [
            make_violation(rule_id="S1", location="CLAUDE.md:1"),
            make_violation(rule_id="S1", location="CLAUDE.md:5"),  # Same file, same rule
        ]
        result = estimate_time_waste(violations)
        assert result["total"] == 2  # Only counted once (medium = 2 min)


class TestGetSeverityPoints:
    """Test get_severity_points function."""

    def test_returns_correct_points_for_each_severity(self) -> None:
        """Returns correct points for each severity level."""
        assert get_severity_points(Severity.CRITICAL) == -25
        assert get_severity_points(Severity.HIGH) == -15
        assert get_severity_points(Severity.MEDIUM) == -10
        assert get_severity_points(Severity.LOW) == -5
