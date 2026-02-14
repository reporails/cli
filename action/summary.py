#!/usr/bin/env python3
"""Generate GitHub Actions step summary markdown from ails check JSON output.

Usage: python3 summary.py '<json_result>'

Outputs markdown to stdout for appending to $GITHUB_STEP_SUMMARY.
"""

from __future__ import annotations

import json
import sys

SEVERITY_ICONS = {
    "critical": "\u274c",  # red X
    "high": "\U0001f7e0",  # orange circle
    "medium": "\u26a0\ufe0f",  # warning
    "low": "\U0001f535",  # blue circle
}


def generate_summary(result: dict) -> str:
    """Generate markdown summary from validation result JSON."""
    lines: list[str] = []

    score = result.get("score", 0)
    level = result.get("level", "?")
    capability = result.get("capability", "")
    violations = result.get("violations", [])
    category_summary = result.get("category_summary", [])
    evaluation = result.get("evaluation", "complete")
    score_delta = result.get("score_delta")

    # Status icon
    if not violations:
        status = "\u2705 Pass"
    elif any(v.get("severity") in ("critical", "high") for v in violations):
        status = "\u274c Fail"
    else:
        status = "\u26a0\ufe0f Warnings"

    # Header
    lines.append("## Reporails Check")
    lines.append("")

    # Score table
    score_display = f"{score:.1f}/10"
    if score_delta is not None and score_delta != 0:
        direction = "+" if score_delta > 0 else ""
        score_display += f" ({direction}{score_delta:.1f})"

    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Score | **{score_display}** |")
    lines.append(f"| Level | **{level}** {capability} |")
    lines.append(f"| Status | {status} |")
    lines.append(f"| Evaluation | {evaluation} |")
    lines.append("")

    # Category summary
    if category_summary:
        lines.append("### Categories")
        lines.append("")
        lines.append("| Category | Passed | Failed | Worst |")
        lines.append("|----------|--------|--------|-------|")
        for cat in category_summary:
            name = cat.get("name", "?")
            passed = cat.get("passed", 0)
            failed = cat.get("failed", 0)
            worst = cat.get("worst_severity", "-")
            icon = SEVERITY_ICONS.get(worst, "") if failed > 0 else "\u2705"
            lines.append(f"| {name.title()} | {passed} | {failed} | {icon} {worst} |")
        lines.append("")

    # Violations table
    if violations:
        lines.append("### Violations")
        lines.append("")
        lines.append("| Severity | Rule | File | Message |")
        lines.append("|----------|------|------|---------|")
        for v in violations:
            sev = v.get("severity", "?")
            icon = SEVERITY_ICONS.get(sev, "")
            rule_id = v.get("rule_id", "?")
            location = v.get("location", "?")
            message = v.get("message", "")
            # Truncate long messages for table readability
            if len(message) > 80:
                message = message[:77] + "..."
            lines.append(f"| {icon} {sev} | `{rule_id}` | `{location}` | {message} |")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        print("## Reporails Check\n\n> No results available.")
        return

    try:
        result = json.loads(sys.argv[1])
    except json.JSONDecodeError:
        print("## Reporails Check\n\n> Failed to parse results.")
        return

    print(generate_summary(result))


if __name__ == "__main__":
    main()
