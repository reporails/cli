"""Rule explanation formatting.

Handles formatting rule details for `ails explain` command.
"""

from __future__ import annotations

from typing import Any


def _append_examples(lines: list[str], examples: dict[str, Any]) -> None:
    """Render Pass / Fail examples, naming their absence rather than omitting silently."""
    pass_ex, fail_ex = examples.get("pass"), examples.get("fail")
    if not pass_ex and not fail_ex:
        lines.append("Examples: none — this rule has no Pass / Fail examples.")
        lines.append("")
        return
    lines.append("Examples:")
    if pass_ex:
        lines.append("  Pass:")
        lines.append(pass_ex)
        lines.append("")
    if fail_ex:
        lines.append("  Fail:")
        lines.append(fail_ex)
        lines.append("")


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
    lines.append("")

    if rule_data.get("description"):
        lines.append("Description:")
        lines.append(f"  {rule_data['description']}")
        lines.append("")

    if "examples" in rule_data:
        _append_examples(lines, rule_data["examples"] or {})

    # Support both checks and legacy antipatterns
    checks = rule_data.get("checks", rule_data.get("antipatterns", []))
    if checks:
        lines.append("Checks:")
        for check in checks:
            label = check.get("name") or check.get("type", "unknown")
            lines.append(f"  - {check.get('id', '?')}: {label} [{check.get('type', '?')}]")
            lines.append(f"    Severity: {check.get('severity', 'medium')}")
        lines.append("")

    see_also = rule_data.get("see_also", [])
    if see_also:
        lines.append("See Also:")
        lines.extend(f"  - {ref}" for ref in see_also)

    return "\n".join(lines)
