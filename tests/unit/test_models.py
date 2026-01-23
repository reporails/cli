"""Unit tests for data models."""

from __future__ import annotations

import pytest

from reporails_cli.core.models import (
    Antipattern,
    Category,
    JudgmentRequest,
    JudgmentResponse,
    Level,
    Rule,
    RuleType,
    Severity,
    UpdateResult,
    ValidationResult,
    Violation,
)


class TestEnums:
    """Test enum definitions."""

    def test_category_values(self) -> None:
        """Category enum has expected values."""
        assert Category.STRUCTURE.value == "structure"
        assert Category.CONTENT.value == "content"
        assert Category.MAINTENANCE.value == "maintenance"
        assert Category.GOVERNANCE.value == "governance"
        assert Category.EFFICIENCY.value == "efficiency"

    def test_rule_type_values(self) -> None:
        """RuleType enum has expected values."""
        assert RuleType.DETERMINISTIC.value == "deterministic"
        assert RuleType.HEURISTIC.value == "heuristic"
        assert RuleType.SEMANTIC.value == "semantic"

    def test_severity_values(self) -> None:
        """Severity enum has expected values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"

    def test_level_values(self) -> None:
        """Level enum has expected values."""
        assert Level.L1.value == "L1"
        assert Level.L6.value == "L6"


class TestAntipattern:
    """Test Antipattern dataclass."""

    def test_create_antipattern(self) -> None:
        """Can create antipattern with all fields."""
        ap = Antipattern(
            id="A1",
            name="Test pattern",
            severity=Severity.HIGH,
            points=-15,
        )
        assert ap.id == "A1"
        assert ap.name == "Test pattern"
        assert ap.severity == Severity.HIGH
        assert ap.points == -15

    def test_antipattern_is_frozen(self) -> None:
        """Antipattern is immutable."""
        ap = Antipattern(id="A1", name="Test", severity=Severity.LOW, points=-5)
        with pytest.raises(AttributeError):
            ap.id = "A2"  # type: ignore[misc]


class TestRule:
    """Test Rule dataclass."""

    def test_create_rule_minimal(self) -> None:
        """Can create rule with required fields only."""
        rule = Rule(
            id="S1",
            title="Size Limits",
            category=Category.STRUCTURE,
            type=RuleType.DETERMINISTIC,
            level="L2+",
            scoring=10,
        )
        assert rule.id == "S1"
        assert rule.title == "Size Limits"
        assert rule.category == Category.STRUCTURE
        assert rule.type == RuleType.DETERMINISTIC
        assert rule.antipatterns == []
        assert rule.md_path is None

    def test_create_rule_with_antipatterns(self) -> None:
        """Can create rule with antipatterns."""
        ap = Antipattern(id="A1", name="Test", severity=Severity.MEDIUM, points=-10)
        rule = Rule(
            id="C1",
            title="Commands",
            category=Category.CONTENT,
            type=RuleType.HEURISTIC,
            level="L2+",
            scoring=10,
            antipatterns=[ap],
        )
        assert len(rule.antipatterns) == 1
        assert rule.antipatterns[0].id == "A1"


class TestViolation:
    """Test Violation dataclass."""

    def test_create_violation(self) -> None:
        """Can create violation."""
        v = Violation(
            rule_id="S1",
            rule_title="Size Limits",
            location="CLAUDE.md:42",
            message="File exceeds 200 lines",
            severity=Severity.CRITICAL,
            points=-25,
        )
        assert v.rule_id == "S1"
        assert v.location == "CLAUDE.md:42"
        assert v.points == -25

    def test_violation_is_frozen(self) -> None:
        """Violation is immutable."""
        v = Violation(
            rule_id="S1",
            rule_title="Test",
            location="test",
            message="test",
            severity=Severity.LOW,
            points=-5,
        )
        with pytest.raises(AttributeError):
            v.points = -10  # type: ignore[misc]


class TestJudgmentRequest:
    """Test JudgmentRequest dataclass."""

    def test_create_judgment_request(self) -> None:
        """Can create judgment request."""
        jr = JudgmentRequest(
            rule_id="C8",
            rule_title="Philosophy",
            content="Some content",
            location="CLAUDE.md",
            question="Is the philosophy clear?",
            criteria={"clarity": "Must be clear"},
            examples={"good": ["Example 1"], "bad": ["Bad example"]},
            choices=["yes", "no"],
            pass_value="yes",
            severity=Severity.HIGH,
            points_if_fail=-15,
        )
        assert jr.rule_id == "C8"
        assert jr.choices == ["yes", "no"]


class TestJudgmentResponse:
    """Test JudgmentResponse dataclass."""

    def test_create_judgment_response(self) -> None:
        """Can create judgment response."""
        jr = JudgmentResponse(
            rule_id="C8",
            verdict="yes",
            reason="Philosophy is clearly stated",
            passed=True,
        )
        assert jr.passed is True


class TestValidationResult:
    """Test ValidationResult dataclass."""

    def test_create_validation_result(self) -> None:
        """Can create validation result."""
        result = ValidationResult(
            score=7.5,
            level=Level.L4,
            violations=(),
            judgment_requests=(),
            rules_checked=10,
            rules_passed=8,
            rules_failed=2,
            time_waste_estimate={"total": 30},
            feature_summary="1 instruction file",
            violation_points=-25,
        )
        assert result.score == 7.5
        assert result.level == Level.L4
        assert result.feature_summary == "1 instruction file"
        assert len(result.violations) == 0

    def test_validation_result_with_violations(self) -> None:
        """Validation result with violations."""
        v = Violation(
            rule_id="S1",
            rule_title="Test",
            location="test",
            message="test",
            severity=Severity.CRITICAL,
            points=-25,
        )
        result = ValidationResult(
            score=7.5,
            level=Level.L4,
            violations=(v,),
            judgment_requests=(),
            rules_checked=10,
            rules_passed=9,
            rules_failed=1,
            time_waste_estimate={"total": 15},
            feature_summary="1 instruction file, .claude/rules/",
            violation_points=-25,
        )
        assert len(result.violations) == 1
        assert result.violations[0].rule_id == "S1"
        assert result.violation_points == -25


class TestUpdateResult:
    """Test UpdateResult dataclass."""

    def test_create_update_result_success(self) -> None:
        """Can create successful update result."""
        from pathlib import Path

        result = UpdateResult(
            success=True,
            message="Updated 10 rules",
            rules_path=Path("/home/user/.reporails/rules"),
            rules_count=10,
        )
        assert result.success is True
        assert result.rules_count == 10

    def test_create_update_result_failure(self) -> None:
        """Can create failed update result."""
        result = UpdateResult(
            success=False,
            message="Network error",
        )
        assert result.success is False
        assert result.rules_path is None
