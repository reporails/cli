"""Unit tests for rule applicability and level-based filtering."""

from __future__ import annotations

from reporails_cli.core.applicability import get_applicable_rules
from reporails_cli.core.models import Category, Level, Rule, RuleType


def _make_rule(rule_id: str, level: str = "L2") -> Rule:
    """Helper to create a minimal Rule."""
    return Rule(
        id=rule_id,
        title=f"Rule {rule_id}",
        category=Category.STRUCTURE,
        type=RuleType.DETERMINISTIC,
        level=level,
        checks=[],
    )


class TestGetApplicableRulesLevelFiltering:
    """Test rule-level-based applicability filtering."""

    def test_rule_at_or_below_level_included(self) -> None:
        """A rule at L2 is included when project is at L3."""
        rules = {"CORE:S:0001": _make_rule("CORE:S:0001", "L2")}

        result = get_applicable_rules(rules, Level.L3)

        assert "CORE:S:0001" in result

    def test_rule_above_level_excluded(self) -> None:
        """A rule at L4 is excluded when project is at L2."""
        rules = {"CORE:S:0001": _make_rule("CORE:S:0001", "L4")}

        result = get_applicable_rules(rules, Level.L2)

        assert "CORE:S:0001" not in result

    def test_rule_at_exact_level_included(self) -> None:
        """A rule at L2 is included when project is at L2."""
        rules = {"CORE:S:0001": _make_rule("CORE:S:0001", "L2")}

        result = get_applicable_rules(rules, Level.L2)

        assert "CORE:S:0001" in result

    def test_supersession_drops_superseded_rule(self) -> None:
        """If rule A supersedes rule B, and both are applicable, B is dropped."""
        rule_a = _make_rule("CORE:S:0010", "L3")
        rule_a.supersedes = "CORE:S:0001"
        rules = {
            "CORE:S:0001": _make_rule("CORE:S:0001", "L2"),
            "CORE:S:0010": rule_a,
        }

        result = get_applicable_rules(rules, Level.L3)

        assert "CORE:S:0001" not in result
        assert "CORE:S:0010" in result
