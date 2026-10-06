"""Capability gating — requires_capability rules fire only for agents that have
the capability.

Covers the pure filter, the matrix loader against the real
framework/capabilities_matrix.yml, and the end-to-end effect through load_rules.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.adapters.registry import clear_rule_cache, load_rules
from reporails_cli.core.platform.config.capabilities import (
    agent_capabilities,
    clear_capability_cache,
    load_capability_matrix,
)
from reporails_cli.core.platform.dto.models import Category, FileMatch, Rule, RuleType
from reporails_cli.core.platform.policy.applicability import filter_by_capability


def _rule(rule_id: str, requires_capability: str | None = None) -> Rule:
    return Rule(
        id=rule_id,
        title="Test",
        category=Category.STRUCTURE,
        type=RuleType.MECHANICAL,
        match=FileMatch(type="memory"),
        slug="test",
        requires_capability=requires_capability,
    )


class TestFilterByCapability:
    """The pure filter — no IO."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_none_capabilities_is_no_gating(self) -> None:
        rules = {"A": _rule("A", requires_capability="memory")}
        assert filter_by_capability(rules, None) == rules

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_rule_without_requirement_always_passes(self) -> None:
        rules = {"A": _rule("A")}
        assert set(filter_by_capability(rules, frozenset())) == {"A"}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_drops_rule_requiring_absent_capability(self) -> None:
        rules = {"A": _rule("A", requires_capability="memory")}
        assert filter_by_capability(rules, frozenset({"skills"})) == {}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_keeps_rule_requiring_present_capability(self) -> None:
        rules = {"A": _rule("A", requires_capability="memory")}
        assert set(filter_by_capability(rules, frozenset({"memory"}))) == {"A"}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_mixed_set(self) -> None:
        rules = {
            "plain": _rule("plain"),
            "needs_memory": _rule("needs_memory", requires_capability="memory"),
            "needs_hooks": _rule("needs_hooks", requires_capability="hooks"),
        }
        kept = filter_by_capability(rules, frozenset({"memory"}))
        assert set(kept) == {"plain", "needs_memory"}


class TestCapabilityMatrix:
    """Loader against the real framework/capabilities_matrix.yml."""

    def setup_method(self) -> None:
        clear_capability_cache()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_matrix_loads_agents(self) -> None:
        matrix = load_capability_matrix()
        assert "claude" in matrix
        assert "memory" in matrix["claude"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_agent_capabilities_case_insensitive(self) -> None:
        assert agent_capabilities("CLAUDE") == agent_capabilities("claude")

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_memory_capable_vs_not(self) -> None:
        assert "memory" in (agent_capabilities("claude") or frozenset())
        assert "memory" not in (agent_capabilities("aider") or frozenset())

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unknown_agent_returns_none(self) -> None:
        assert agent_capabilities("not-a-real-agent") is None

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_empty_agent_returns_none(self) -> None:
        assert agent_capabilities("") is None


class TestLoadRulesGating:
    """End-to-end: the memory-directory rule is gated on the `memory` capability."""

    MEMORY_RULE = "CORE:S:0023"  # agent-memory-directory, requires_capability: memory

    def setup_method(self) -> None:
        clear_rule_cache()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize("agent", ["claude", "codex", "cursor"])
    def test_memory_capable_agent_keeps_rule(self, agent: str) -> None:
        rules = load_rules(agent=agent)
        assert self.MEMORY_RULE in rules

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize("agent", ["aider", "warp"])
    def test_memory_lacking_agent_drops_rule(self, agent: str) -> None:
        rules = load_rules(agent=agent)
        assert self.MEMORY_RULE not in rules

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_agent_agnostic_scan_keeps_rule(self) -> None:
        rules = load_rules(agent="")
        assert self.MEMORY_RULE in rules


class TestEnforcementFields:
    """Enforcement fields flow from frontmatter through the DTO."""

    def setup_method(self) -> None:
        clear_rule_cache()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_ci_enforcement_rule(self) -> None:
        rules = load_rules(agent="claude")
        no_creds = rules["CORE:G:0002"]  # no-credentials
        assert no_creds.enforcement_required is True
        assert no_creds.enforcement_mechanism == "ci"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_hook_enforcement_rule(self) -> None:
        rules = load_rules(agent="claude")
        hook_rule = rules["CLAUDE:S:0004"]  # hook-command-has-field
        assert hook_rule.enforcement_required is True
        assert hook_rule.enforcement_mechanism == "hook"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_non_enforcement_rule_defaults_false(self) -> None:
        rules = load_rules(agent="claude")
        # A content-quality rule carries no enforcement partner.
        directive = rules["CORE:D:0001"]  # directive-density
        assert directive.enforcement_required is False
        assert directive.enforcement_mechanism is None
