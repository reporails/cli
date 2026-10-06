"""Rule applicability — capability gating for the loaded rule set.

Drops rules that require a capability the selected agent lacks; a rule with
no capability requirement always passes.
"""

from __future__ import annotations

from reporails_cli.core.platform.dto.models import Rule


def filter_by_capability(
    rules: dict[str, Rule],
    agent_capabilities: frozenset[str] | None,
) -> dict[str, Rule]:
    """Drop rules that require a capability the agent does not have.

    A rule with no `requires_capability` always passes. When
    `agent_capabilities` is None (agent unknown or an agent-agnostic scan),
    no gating is applied and every rule passes.

    Args:
        rules: Dict of rules to filter
        agent_capabilities: The agent's capability set, or None for no gating

    Returns:
        Dict of rules the agent's capabilities admit
    """
    if agent_capabilities is None:
        return rules
    return {
        rule_id: rule
        for rule_id, rule in rules.items()
        if not rule.requires_capability or rule.requires_capability in agent_capabilities
    }
