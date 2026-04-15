"""MCP output formatter — compact format optimized for LLM context windows.

Builds responses directly from domain models instead of delegating to the
CLI JSON formatter.  Violations are grouped by file with positional arrays,
judgment requests use short keys, and whitespace is eliminated by the server.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from reporails_cli.core.models import ScanDelta, ValidationResult

if TYPE_CHECKING:
    from reporails_cli.core.fixers import FixResult
    from reporails_cli.core.models import JudgmentRequest, Violation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MSG_MAX = 80


def _line_ref(location: str, file_key: str) -> str:
    """Extract ':line' portion relative to the file group key.

    >>> _line_ref("CLAUDE.md:45", "CLAUDE.md")
    ':45'
    >>> _line_ref("CLAUDE.md", "CLAUDE.md")
    ''
    """
    if location.startswith(file_key) and len(location) > len(file_key) and location[len(file_key)] == ":":
        return location[len(file_key) :]
    return ""


def _file_from_location(location: str) -> str:
    """Extract file path from a location string (drop :line suffix)."""
    # location may be "path/to/file.md:42" or just "path/to/file.md"
    parts = location.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return location


def _truncate(text: str, limit: int = _MSG_MAX) -> str:
    return (text[: limit - 1] + "\u2026") if len(text) > limit else text


# ---------------------------------------------------------------------------
# Violations  — grouped by file, positional arrays
# ---------------------------------------------------------------------------


def _group_violations(violations: tuple[Violation, ...]) -> dict[str, list[list[str]]]:
    """Group violations by file as ``{file: [[rule_id, line_ref, severity, message], ...]}``."""
    grouped: dict[str, list[list[str]]] = {}
    for v in violations:
        fkey = _file_from_location(v.location)
        entry = [
            v.rule_id,
            _line_ref(v.location, fkey),
            v.severity.value,
            _truncate(v.message),
        ]
        grouped.setdefault(fkey, []).append(entry)
    return grouped


# ---------------------------------------------------------------------------
# Judgment requests — compact dicts with short keys
# ---------------------------------------------------------------------------

# Default criteria values that can be elided
_DEFAULT_CRITERIA: dict[str, str] = {}


def _compact_judgment(jr: JudgmentRequest) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": jr.rule_id,
        "loc": _file_from_location(jr.location),
        "q": jr.question,
    }
    if jr.criteria and jr.criteria != _DEFAULT_CRITERIA:
        d["criteria"] = jr.criteria
    return d


# ---------------------------------------------------------------------------
# Delta — only non-null fields with short keys
# ---------------------------------------------------------------------------


def _compact_delta(delta: ScanDelta | None) -> dict[str, Any] | None:
    if delta is None:
        return None
    d: dict[str, Any] = {}
    if delta.score_delta is not None:
        d["score_delta"] = delta.score_delta
    if delta.level_previous is not None:
        d["level_prev"] = delta.level_previous
    if delta.level_improved is not None:
        d["level_up"] = delta.level_improved
    if delta.violations_delta is not None:
        d["viol_delta"] = delta.violations_delta
    return d or None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def format_result(
    result: ValidationResult,
    delta: ScanDelta | None = None,
) -> dict[str, Any]:
    """Format validation result as compact MCP response.

    Returns:
        Dict with score, level, checked, failed, friction, violations (grouped
        by file), judgment_requests (compact), and optional delta.
    """
    data: dict[str, Any] = {
        "score": result.score,
        "level": result.level.value,
        "checked": result.rules_checked,
        "failed": result.rules_failed,
        "friction": result.friction.level if result.friction else "none",
    }

    violations = _group_violations(result.violations)
    if violations:
        data["violations"] = violations

    jrs = [_compact_judgment(jr) for jr in result.judgment_requests]
    if jrs:
        data["judgment_requests"] = jrs

    d = _compact_delta(delta)
    if d:
        data["delta"] = d

    return data


def format_score(result: ValidationResult) -> dict[str, Any]:
    """Format quick score response for MCP."""
    from reporails_cli.formatters import json as json_formatter

    return json_formatter.format_score(result)


def format_heal_result(
    fixes: list[FixResult],
    judgment_requests: list[JudgmentRequest],
    *,
    non_fixable: list[Violation] | None = None,
) -> dict[str, Any]:
    """Format heal result as compact MCP response.

    Returns:
        Dict with auto_fixed, compact judgment_requests, and optional
        non-fixable violations.
    """
    data: dict[str, Any] = {
        "auto_fixed": [
            {
                "rule_id": f.rule_id,
                "file_path": f.file_path,
                "description": f.description,
            }
            for f in fixes
        ],
    }

    jrs = [_compact_judgment(jr) for jr in judgment_requests]
    if jrs:
        data["judgment_requests"] = jrs

    if non_fixable:
        data["violations"] = [
            {
                "rule_id": v.rule_id,
                "location": v.location,
                "message": _truncate(v.message),
                "severity": v.severity.value,
            }
            for v in non_fixable
        ]

    return data


def format_rule(rule_id: str, rule_data: dict[str, Any]) -> str:
    """Format rule explanation as readable text for MCP.

    Unlike validate/score/heal (which return compact JSON for agent parsing),
    explain returns human-readable text since its purpose is explanation.
    """
    title = rule_data.get("title", "")
    severity = rule_data.get("severity", "medium")

    parts = [f"{rule_id} — {title}"]

    meta = [f"severity: {severity}"]
    scope = rule_data.get("match", {})
    if scope and scope.get("type"):
        meta.append(f"scope: {scope['type']}")
    parts.append(" | ".join(meta))
    parts.append("")

    desc = rule_data.get("description", "")
    if desc:
        # Strip the markdown heading (already shown as title)
        lines = desc.strip().splitlines()
        body = "\n".join(
            line for line in lines if not (line.startswith("# ") and title.lower() in line.lower())
        ).strip()
        if body:
            parts.append(body)
            parts.append("")

    checks = rule_data.get("checks", [])
    if checks:
        parts.append("Checks:")
        parts.extend(f"  {c.get('id', '?')} ({c.get('type', '?')})" for c in checks)

    see_also = rule_data.get("see_also", [])
    if see_also:
        parts.append("")
        parts.append("See also: " + ", ".join(see_also))

    return "\n".join(parts)
