"""Rule explanation formatting.

Handles formatting rule details for `ails explain` command.
"""

from __future__ import annotations

from typing import Any


def format_rule(rule_id: str, rule_data: dict[str, Any]) -> str:
    """Format rule explanation for terminal."""
    lines = []

    lines.append(f"Rule: {rule_id}")
    lines.append("=" * 60)
    lines.append("")

    if rule_data.get("title"):
        lines.append(f"Title: {rule_data['title']}")
    if rule_data.get("category"):
        lines.append(f"Category: {rule_data['category']}")
    if rule_data.get("type"):
        lines.append(f"Type: {rule_data['type']}")
    if rule_data.get("level"):
        lines.append(f"Required Level: {rule_data['level']}")

    lines.append("")

    if rule_data.get("description"):
        lines.append("Description:")
        lines.append(f"  {rule_data['description']}")
        lines.append("")

    # Support both checks and legacy antipatterns
    checks = rule_data.get("checks", rule_data.get("antipatterns", []))
    if checks:
        lines.append("Checks:")
        for check in checks:
            lines.append(f"  - {check.get('id', '?')}: {check.get('name', 'Unknown')}")
            lines.append(f"    Severity: {check.get('severity', 'medium')}")
        lines.append("")

    see_also = rule_data.get("see_also", [])
    if see_also:
        lines.append("See Also:")
        lines.extend(f"  - {ref}" for ref in see_also)

    return "\n".join(lines)
