#!/usr/bin/env python3
"""Generate GitHub Actions step summary markdown from ails check JSON output.

Usage: REPORAILS_RESULT='<json>' python3 summary.py

Reads JSON from the REPORAILS_RESULT environment variable.
Outputs markdown to stdout for appending to $GITHUB_STEP_SUMMARY.
"""

from __future__ import annotations

import json
import os

SEVERITY_ICONS = {
    "error": "\u274c",
    "high": "\U0001f7e0",
    "medium": "\u26a0\ufe0f",
    "warning": "\u26a0\ufe0f",
    "info": "\U0001f535",
}


def generate_summary(result: dict) -> str:
    """Generate markdown summary from CombinedResult JSON."""
    lines: list[str] = []

    files = result.get("files", {})
    stats = result.get("stats", {})
    offline = result.get("offline", True)

    total_findings = sum(f.get("count", 0) for f in files.values())
    errors = stats.get("errors", 0)
    warnings = stats.get("warnings", 0)

    # Status icon
    if total_findings == 0:
        status = "\u2705 Pass"
    elif errors > 0:
        status = "\u274c Fail"
    else:
        status = "\u26a0\ufe0f Warnings"

    # Header
    lines.append("## Reporails Check")
    lines.append("")

    mode = "offline" if offline else "online"
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Status | {status} |")
    lines.append(f"| Findings | **{total_findings}** ({errors} errors, {warnings} warnings) |")
    lines.append(f"| Files | {len(files)} |")
    lines.append(f"| Mode | {mode} |")
    lines.append("")

    # Findings table
    if files:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Severity | Rule | File | Message |")
        lines.append("|----------|------|------|---------|")
        for filepath, file_data in files.items():
            for f in file_data.get("findings", []):
                sev = f.get("severity", "?")
                icon = SEVERITY_ICONS.get(sev, "")
                rule = f.get("rule", "?")
                line = f.get("line", 0)
                location = f"{filepath}:{line}" if line else filepath
                message = f.get("message", "")
                if len(message) > 80:
                    message = message[:77] + "..."
                lines.append(f"| {icon} {sev} | `{rule}` | `{location}` | {message} |")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    raw = os.environ.get("REPORAILS_RESULT", "").strip()
    if not raw:
        print("## Reporails Check\n\n> No results available.")
        return

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        print("## Reporails Check\n\n> Failed to parse results.")
        return

    print(generate_summary(result))


if __name__ == "__main__":
    main()
