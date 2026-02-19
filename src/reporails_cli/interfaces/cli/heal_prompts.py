"""Interactive prompt helpers and cache helpers for ails heal.

Extracted from heal.py to keep module under the line limit.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.cache import cache_judgments

if TYPE_CHECKING:
    from reporails_cli.core.models import JudgmentRequest, Violation


# ---------------------------------------------------------------------------
# Non-interactive output
# ---------------------------------------------------------------------------


def run_non_interactive(
    fixable: list[Violation],
    non_fixable: list[Violation],
    requests: list[JudgmentRequest],
    target: Path,
) -> None:
    """Non-interactive mode: auto-fix and output JSON."""
    import json

    from reporails_cli.core.fixers import apply_auto_fixes
    from reporails_cli.formatters import json as json_formatter

    fixes = apply_auto_fixes(fixable, target)

    auto_fixed_data = [
        {
            "rule_id": fix.rule_id,
            "file_path": str(Path(fix.file_path).relative_to(target))
            if Path(fix.file_path).is_relative_to(target)
            else fix.file_path,
            "description": fix.description,
        }
        for fix in fixes
    ]

    violation_data = [
        {
            "rule_id": v.rule_id,
            "rule_title": v.rule_title,
            "location": v.location,
            "message": v.message,
            "severity": v.severity.value,
        }
        for v in non_fixable
    ]

    judgment_data = [
        {
            "rule_id": jr.rule_id,
            "rule_title": jr.rule_title,
            "question": jr.question,
            "content": jr.content,
            "location": jr.location,
            "criteria": jr.criteria,
            "examples": jr.examples,
            "choices": jr.choices,
            "pass_value": jr.pass_value,
        }
        for jr in requests
    ]

    output = json_formatter.format_heal_result(
        auto_fixed_data,
        judgment_data,
        violations=violation_data,
    )
    print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

_fix_legend_shown = False


def prompt_fix_action() -> str:
    """Prompt for [a]pply / [s]kip / [d]ismiss."""
    global _fix_legend_shown
    if not _fix_legend_shown:
        print()
        print("  [a]pply   — apply the proposed fix")
        print("  [s]kip    — decide later")
        print("  [d]ismiss — not applicable to this project")
        _fix_legend_shown = True
    while True:
        try:
            choice = input("\n  Action [a/s/d]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "s"
        if choice in ("a", "s", "d"):
            return choice
        print("  Please enter a (apply), s (skip), or d (dismiss).")


_violation_legend_shown = False


def prompt_violation_action() -> str:
    """Prompt for [d]ismiss / [s]kip."""
    global _violation_legend_shown
    if not _violation_legend_shown:
        print()
        print("  [d]ismiss — not applicable to this project (hides from future runs)")
        print("  [s]kip    — decide later")
        _violation_legend_shown = True
    while True:
        try:
            choice = input("\n  Action [d/s]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "s"
        if choice in ("d", "s"):
            return choice
        print("  Please enter d (dismiss) or s (skip).")


_verdict_legend_shown = False


def prompt_verdict() -> str:
    """Prompt for [p]ass / [f]ail / [s]kip / [d]ismiss."""
    global _verdict_legend_shown
    if not _verdict_legend_shown:
        print()
        print("  [p]ass    — rule is satisfied")
        print("  [f]ail    — rule not satisfied (you'll provide a reason)")
        print("  [s]kip    — decide later")
        print("  [d]ismiss — not applicable to this project")
        _verdict_legend_shown = True
    while True:
        try:
            choice = input("\n  Your verdict [p/f/s/d]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "s"
        if choice in ("p", "f", "s", "d"):
            return choice
        print("  Please enter p (pass), f (fail), s (skip), or d (dismiss).")


def prompt_reason() -> str:
    """Prompt for failure reason (required)."""
    while True:
        try:
            reason = input("  Reason: ").strip()
        except (EOFError, KeyboardInterrupt):
            return "No reason provided"
        if reason:
            return reason
        print("  Reason is required for failures.")


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


def cache_verdict(target: Path, jr: JudgmentRequest, verdict: str, reason: str) -> None:
    """Cache a single semantic verdict using the existing cache_judgments pipeline."""
    file_path = jr.location.rsplit(":", 1)[0] if ":" in jr.location else jr.location
    with contextlib.suppress(ValueError):
        file_path = str(Path(file_path).relative_to(target))

    cache_judgments(
        target,
        [
            {
                "rule_id": jr.rule_id,
                "location": file_path,
                "verdict": verdict,
                "reason": reason,
            }
        ],
    )


def cache_violation_dismissal(target: Path, violation: Violation) -> None:
    """Cache a violation dismissal as a 'pass' verdict in the judgment cache."""
    file_path = violation.location.rsplit(":", 1)[0] if ":" in violation.location else violation.location
    with contextlib.suppress(ValueError):
        file_path = str(Path(file_path).relative_to(target))

    cache_judgments(
        target,
        [
            {
                "rule_id": violation.rule_id,
                "location": file_path,
                "verdict": "pass",
                "reason": "Dismissed via ails heal",
            }
        ],
    )
