"""Rule applicability — pure decision: which rules apply to which file types.

A rule fires when its target file type is present (or it is a wildcard).
Supersession within the applicable set lets agent overlays replace core
rules without each layer re-declaring the same checks.
"""

from __future__ import annotations

from reporails_cli.core.platform.dto.models import Rule


def get_applicable_rules(
    rules: dict[str, Rule],
    present_types: set[str],
) -> dict[str, Rule]:
    """Filter rules to those whose target file type exists.

    A rule fires when:
    - rule.match.type is in present_types, OR
    - rule.match is None / rule.match.type is None (wildcard — fires if any type present)

    If rule A supersedes rule B, and both are applicable, drop B.

    Args:
        rules: Dict of all rules
        present_types: Set of file type names present in the project

    Returns:
        Dict of applicable rules
    """
    if not present_types:
        return {}

    applicable: dict[str, Rule] = {}
    for rule_id, rule in rules.items():
        if rule.match is None or rule.match.type is None:
            # Wildcard — fires if any type present
            applicable[rule_id] = rule
        elif isinstance(rule.match.type, list):
            if any(t in present_types for t in rule.match.type):
                applicable[rule_id] = rule
        elif rule.match.type in present_types:
            applicable[rule_id] = rule

    # Handle supersession within applicable set.
    # NOTE: load_rules() already handles supersession at load time, but this
    # covers cases where rules are constructed without load_rules() (e.g., tests)
    # and the edge case where a superseding rule's target type is absent.
    superseded_ids: set[str] = set()
    for rule_id, rule in list(applicable.items()):
        if rule.supersedes and rule.supersedes in applicable:
            superseded_ids.add(rule.supersedes)
            parent = applicable[rule.supersedes]
            # Inherit parent checks that aren't replaced by the agent rule
            replaced_ids = {c.replaces for c in rule.checks if c.replaces}
            inherited = [c for c in parent.checks if c.id not in replaced_ids]
            applicable[rule_id] = rule.model_copy(update={"checks": inherited + list(rule.checks)})

    if superseded_ids:
        applicable = {k: v for k, v in applicable.items() if k not in superseded_ids}

    return applicable
