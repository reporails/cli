"""Heal command output formatting — autoheal summary rendering."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.fixers import FixResult
from reporails_cli.core.models import JudgmentRequest, Violation


def format_heal_summary(
    fixes: list[FixResult],
    non_fixable: list[Violation],
    requests: list[JudgmentRequest],
    *,
    ascii_mode: bool = False,
) -> str:
    """Format the autoheal summary with applied fixes, remaining violations, and pending rules."""
    check = "+" if ascii_mode else "\u2713"
    cross = "x" if ascii_mode else "\u2717"
    question = "?"

    sections: list[str] = []

    # Applied fixes
    if fixes:
        lines = [
            f"Applied {len(fixes)} fix(es):",
            *[f"  {check} {fix.rule_id} \u2014 {fix.description}" for fix in fixes],
        ]
        sections.append("\n".join(lines))

    # Remaining violations
    if non_fixable:
        lines = [
            f"{len(non_fixable)} remaining violation(s):",
            *[f"  {cross} {v.rule_id} \u2014 {v.message} ({v.location})" for v in non_fixable],
        ]
        sections.append("\n".join(lines))

    # Pending semantic rules
    if requests:
        lines = [
            f"{len(requests)} semantic rule(s) pending evaluation:",
            *[f"  {question} {jr.rule_id} \u2014 {jr.rule_title} ({jr.location})" for jr in requests],
        ]
        sections.append("\n".join(lines))

    if not sections:
        return "Nothing to heal. All rules pass or are cached."

    return "\n\n".join(sections)


def extract_violation_snippet(
    location: str,
    scan_root: Path,
    context_lines: int = 2,
) -> str | None:
    """Read file and return lines around the violation with a >> marker.

    Returns None on read error or if the location has no line number.
    """
    parts = location.rsplit(":", 1)
    if len(parts) != 2 or not parts[1].isdigit():
        return None

    file_part, line_str = parts
    target_line = int(line_str)
    file_path = Path(file_part)
    if not file_path.is_absolute():
        file_path = scan_root / file_path

    try:
        all_lines = file_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    if target_line < 1 or target_line > len(all_lines):
        return None

    start = max(0, target_line - 1 - context_lines)
    end = min(len(all_lines), target_line + context_lines)
    snippet_lines: list[str] = []
    for i in range(start, end):
        line_num = i + 1
        marker = ">>" if line_num == target_line else "  "
        snippet_lines.append(f"{marker} {line_num:>4} | {all_lines[i]}")
    return "\n".join(snippet_lines)
