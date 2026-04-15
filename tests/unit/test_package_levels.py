"""Unit tests for rule applicability with target existence filtering."""

from __future__ import annotations

from dataclasses import replace

from reporails_cli.core.applicability import get_applicable_rules
from reporails_cli.core.models import Category, FileMatch, Rule, RuleType


def _make_rule(rule_id: str, match_type: str = "main") -> Rule:
    """Helper to create a minimal Rule."""
    return Rule(
        id=rule_id,
        title=f"Rule {rule_id}",
        category=Category.STRUCTURE,
        type=RuleType.DETERMINISTIC,
        match=FileMatch(type=match_type),
        checks=[],
    )


class TestGetApplicableRulesTargetFiltering:
    """Test target-existence-based applicability filtering."""

    def test_rule_included_when_target_present(self) -> None:
        """A rule targeting 'main' is included when 'main' is present."""
        rules = {"CORE:S:0001": _make_rule("CORE:S:0001", "main")}

        result = get_applicable_rules(rules, {"main"})

        assert "CORE:S:0001" in result

    def test_rule_excluded_when_target_absent(self) -> None:
        """A rule targeting 'config' is excluded when 'config' is not present."""
        rules = {"CORE:S:0001": _make_rule("CORE:S:0001", "config")}

        result = get_applicable_rules(rules, {"main"})

        assert "CORE:S:0001" not in result

    def test_supersession_drops_superseded_rule(self) -> None:
        """If rule A supersedes rule B, and both are applicable, B is dropped."""
        rule_a = replace(_make_rule("CORE:S:0010"), supersedes="CORE:S:0001")
        rules = {
            "CORE:S:0001": _make_rule("CORE:S:0001"),
            "CORE:S:0010": rule_a,
        }

        result = get_applicable_rules(rules, {"main"})

        assert "CORE:S:0001" not in result
        assert "CORE:S:0010" in result
