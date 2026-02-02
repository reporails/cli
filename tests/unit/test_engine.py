"""Unit tests for engine — only the pure _compute_category_summary function."""

from __future__ import annotations

from reporails_cli.core.engine import _compute_category_summary
from reporails_cli.core.models import Category, Rule, RuleType, Severity, Violation


def _rule(rule_id: str, category: Category) -> Rule:
    return Rule(
        id=rule_id,
        title=f"Rule {rule_id}",
        category=category,
        type=RuleType.DETERMINISTIC,
        level="L2",
    )


def _violation(rule_id: str, severity: Severity = Severity.MEDIUM) -> Violation:
    return Violation(
        rule_id=rule_id,
        rule_title="Test",
        location="test.md:1",
        message="msg",
        severity=severity,
    )


class TestComputeCategorySummary:
    def test_all_passing(self) -> None:
        rules = {
            "S1": _rule("S1", Category.STRUCTURE),
            "C1": _rule("C1", Category.CONTENT),
        }
        stats = _compute_category_summary(rules, [])

        s_stat = next(s for s in stats if s.code == "S")
        c_stat = next(s for s in stats if s.code == "C")
        assert s_stat.total == 1 and s_stat.failed == 0 and s_stat.passed == 1
        assert c_stat.total == 1 and c_stat.failed == 0 and c_stat.passed == 1

    def test_mixed_violations(self) -> None:
        rules = {
            "S1": _rule("S1", Category.STRUCTURE),
            "S2": _rule("S2", Category.STRUCTURE),
            "C1": _rule("C1", Category.CONTENT),
            "E1": _rule("E1", Category.EFFICIENCY),
        }
        violations = [
            _violation("S1", Severity.HIGH),
            _violation("C1", Severity.LOW),
        ]
        stats = _compute_category_summary(rules, violations)

        s_stat = next(s for s in stats if s.code == "S")
        c_stat = next(s for s in stats if s.code == "C")
        e_stat = next(s for s in stats if s.code == "E")
        assert s_stat.failed == 1 and s_stat.passed == 1 and s_stat.worst_severity == "high"
        assert c_stat.failed == 1 and c_stat.passed == 0 and c_stat.worst_severity == "low"
        assert e_stat.failed == 0 and e_stat.passed == 1 and e_stat.worst_severity is None

    def test_empty_rules(self) -> None:
        stats = _compute_category_summary({}, [])
        for s in stats:
            assert s.total == 0 and s.failed == 0 and s.passed == 0

    def test_worst_severity_across_violations(self) -> None:
        rules = {"S1": _rule("S1", Category.STRUCTURE), "S2": _rule("S2", Category.STRUCTURE)}
        violations = [
            _violation("S1", Severity.LOW),
            _violation("S2", Severity.CRITICAL),
        ]
        stats = _compute_category_summary(rules, violations)
        s_stat = next(s for s in stats if s.code == "S")
        assert s_stat.worst_severity == "critical"
