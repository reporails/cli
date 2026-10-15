"""Rule explanation formatting.

Handles formatting rule details for `ails explain` command.
"""

from __future__ import annotations

from reporails_cli.core.platform.contract.json_value import JsonObject, as_list, as_object, as_str


def _append_examples(lines: list[str], examples: JsonObject) -> None:
    """Render Pass / Fail examples, naming their absence rather than omitting silently."""
    pass_ex, fail_ex = examples.get("pass"), examples.get("fail")
    if not pass_ex and not fail_ex:
        lines.append("Examples: none — this rule has no Pass / Fail examples.")
        lines.append("")
        return
    lines.append("Examples:")
    if pass_ex:
        lines.append("  Pass:")
        lines.append(as_str(pass_ex))
        lines.append("")
    if fail_ex:
        lines.append("  Fail:")
        lines.append(as_str(fail_ex))
        lines.append("")


def format_rule(rule_id: str, rule_data: JsonObject) -> str:
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
    if rule_data.get("severity"):
        lines.append(f"Severity: {rule_data['severity']}")
    if rule_data.get("execution") == "server":
        lines.append("Execution: server (needs a server connection; the remedies are part of Pro)")
    match = as_object(rule_data.get("match"))
    if match:
        # Single-sourced from `serialize_match` (the same dict `ails rules list` emits) so a
        # rule author who sets e.g. `content_format` / `loading_verb` / `link_source_type` sees
        # it here too, not only in the JSON listing.
        lines.append(
            "Match: "
            + ", ".join(
                f"{k}: {', '.join(str(item) for item in v) if isinstance(v, list) else v}" for k, v in match.items()
            )
        )
    lines.append("")

    if rule_data.get("description"):
        lines.append("Description:")
        lines.append(f"  {rule_data['description']}")
        lines.append("")

    if "examples" in rule_data:
        _append_examples(lines, as_object(rule_data["examples"]))

    # Support both checks and legacy antipatterns
    checks = as_list(rule_data.get("checks", rule_data.get("antipatterns", [])))
    if checks:
        lines.append("Checks:")
        for check_value in checks:
            check = as_object(check_value)
            label = check.get("name") or check.get("type", "unknown")
            lines.append(f"  - {check.get('id', '?')}: {label} [{check.get('type', '?')}]")
            # A check's own severity overrides the rule's; an unset check severity
            # inherits the rule's, never a hard-coded default.
            severity = check.get("severity") or rule_data.get("severity") or "medium"
            lines.append(f"    Severity: {severity}")
        lines.append("")

    see_also = as_list(rule_data.get("see_also", []))
    if see_also:
        lines.append("See Also:")
        lines.extend(f"  - {ref}" for ref in see_also)

    return "\n".join(lines)
