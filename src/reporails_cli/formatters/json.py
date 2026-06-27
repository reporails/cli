"""Canonical JSON serialization for ValidationResult.

This is the single source of truth for serializing validation results.
All other formatters consume this format internally.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.platform.dto.models import (
    CategoryStats,
    PendingSemantic,
    RuleResult,
    ScanDelta,
    ValidationResult,
)
from reporails_cli.core.platform.policy.levels import LEVEL_LABELS


def _format_pending_semantic(pending: PendingSemantic | None) -> dict[str, Any] | None:
    """Format pending semantic rules for JSON output."""
    if pending is None:
        return None
    return {
        "rule_count": pending.rule_count,
        "file_count": pending.file_count,
        "rules": list(pending.rules),
    }


def _format_rule_results(results: tuple[RuleResult, ...]) -> list[dict[str, str]]:
    """Format per-rule pass/fail for JSON output."""
    return [{"rule_id": r.rule_id, "status": r.status} for r in results]


def _format_category_summary(summary: tuple[CategoryStats, ...]) -> list[dict[str, Any]]:
    """Format category summary for JSON output."""
    return [
        {
            "code": cs.code,
            "name": cs.name,
            "total": cs.total,
            "passed": cs.passed,
            "failed": cs.failed,
            "worst_severity": cs.worst_severity,
        }
        for cs in summary
    ]


def format_result(
    result: ValidationResult,
    delta: ScanDelta | None = None,
) -> dict[str, Any]:
    """Convert ValidationResult to canonical dict format.

    This is the single source of truth for result serialization.

    Args:
        result: ValidationResult from engine
        delta: Optional ScanDelta for comparison with previous run

    Returns:
        Canonical dict representation
    """
    data: dict[str, Any] = {
        "score": result.score,
        "level": result.level.value,
        "capability": LEVEL_LABELS.get(result.level, "Unknown"),
        "feature_summary": result.feature_summary,
        "summary": {
            "rules_checked": result.rules_checked,
            "rules_passed": result.rules_passed,
            "rules_failed": result.rules_failed,
        },
        "violations": [
            {
                "rule_id": v.rule_id,
                "rule_title": v.rule_title,
                "location": v.location,
                "message": v.message,
                "severity": v.severity.value,
                "check_id": v.check_id,
            }
            for v in result.violations
        ],
        "judgment_requests": [
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
            for jr in result.judgment_requests
        ],
        "friction": result.friction.level if result.friction else "none",
        "category_summary": _format_category_summary(result.category_summary),
        "rule_results": _format_rule_results(result.rule_results),
        # Evaluation completeness
        "evaluation": "awaiting_semantic" if result.is_partial else "complete",
        "is_partial": result.is_partial,
    }

    # Optional fields — omit when absent to avoid null-chaining bugs in consumers
    pending = _format_pending_semantic(result.pending_semantic)
    if pending is not None:
        data["pending_semantic"] = pending

    # Add delta fields (null if no previous run or unchanged)
    if delta is not None:
        data["score_delta"] = delta.score_delta
        data["level_previous"] = delta.level_previous
        data["level_improved"] = delta.level_improved
        data["violations_delta"] = delta.violations_delta
    else:
        data["score_delta"] = None
        data["level_previous"] = None
        data["level_improved"] = None
        data["violations_delta"] = None

    return data


def format_score(result: ValidationResult) -> dict[str, Any]:
    """Convert ValidationResult to minimal score dict.

    Args:
        result: ValidationResult from engine

    Returns:
        Simplified dict with just score info
    """
    return {
        "score": result.score,
        "level": result.level.value,
        "capability": LEVEL_LABELS.get(result.level, "Unknown"),
        "feature_summary": result.feature_summary,
        "rules_checked": result.rules_checked,
        "violations_count": len(result.violations),
        "has_critical": any(v.severity.value == "critical" for v in result.violations),
        "friction": result.friction.level if result.friction else "none",
    }


def format_rule(rule_id: str, rule_data: dict[str, Any]) -> dict[str, Any]:
    """Format rule explanation as dict.

    Args:
        rule_id: Rule identifier
        rule_data: Rule metadata

    Returns:
        Dict with rule details
    """
    result: dict[str, Any] = {
        "id": rule_id,
        "title": rule_data.get("title", ""),
        "category": rule_data.get("category", ""),
        "type": rule_data.get("type", ""),
    }
    match = rule_data.get("match")
    if match:
        result["scope"] = match
    result["description"] = rule_data.get("description", "")
    result["checks"] = rule_data.get("checks", rule_data.get("antipatterns", []))
    result["see_also"] = rule_data.get("see_also", [])
    return result


def format_heal_result(
    auto_fixed: list[dict[str, Any]],
    judgment_requests: list[dict[str, Any]],
    *,
    violations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Format heal command results as JSON.

    Args:
        auto_fixed: List of auto-fix entries (rule_id, file_path, description)
        judgment_requests: List of semantic judgment requests
        violations: Optional list of non-fixable violations requiring manual attention

    Returns:
        Dict with auto_fixed, violations, and judgment_requests
    """
    result: dict[str, Any] = {
        "auto_fixed": auto_fixed,
        "judgment_requests": judgment_requests,
        "summary": {
            "auto_fixed_count": len(auto_fixed),
            "pending_judgments": len(judgment_requests),
        },
    }
    if violations:
        result["violations"] = violations
        result["summary"]["violations_count"] = len(violations)
    return result


def _category_for_rule(rule_id: str) -> str:
    """Derive the category label for a rule ID via `CATEGORY_CODES`.

    Returns the lowercase Category value (`"structure"`, `"direction"`, etc.)
    when the rule ID's second segment matches a known code, or an empty
    string when the shape is unrecognized. The MCP / JSON consumer reads
    this to group findings by category for prioritization.
    """
    from reporails_cli.core.platform.dto.models import CATEGORY_CODES

    parts = rule_id.split(":")
    if len(parts) < 2:
        return ""
    category = CATEGORY_CODES.get(parts[1])
    return category.value if category else ""


def _regime_by_file(result: Any, project_root: Path) -> dict[str, dict[str, Any]]:
    """Build a file-keyed map of additive regime fields from server analysis stats.

    Only `named` / `within_capacity` / `confidence` are exposed — a structural
    read, no equation-derived numbers. Empty for offline runs.
    """
    from reporails_cli.core.platform.policy.leverage import classify_regime
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    out: dict[str, dict[str, Any]] = {}
    for fa in getattr(result, "per_file_analysis", ()):  # absent on offline-only shapes
        regime = classify_regime(fa.stats)
        if regime is not None:
            # Key by the same project-relative form the `files` dict uses
            # (findings are already normalized; server `per_file` is absolute).
            out[normalize_finding_path(fa.file, project_root)] = {
                "named": regime.named,
                "within_capacity": regime.within_capacity,
                "confidence": round(regime.confidence, 2),
            }
    return out


def _pro_summary(hints: Any) -> dict[str, int]:
    """Aggregate pro-tier hint counts into the JSON `pro` block."""
    return {
        "count": sum(h.count for h in hints),
        "errors": sum(getattr(h, "error_count", 0) for h in hints),
        "warnings": sum(getattr(h, "warning_count", 0) for h in hints),
    }


def _file_entry(findings: list[dict[str, Any]], regime: dict[str, Any] | None) -> dict[str, Any]:
    """Build one per-file JSON entry, attaching `regime` when available (additive)."""
    entry: dict[str, Any] = {"findings": findings, "count": len(findings)}
    if regime is not None:
        entry["regime"] = regime
    return entry


def format_combined_result(
    result: Any,
    ruleset_map: Any = None,
    project_root: Path | None = None,
    file_type_by_path: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Format CombinedResult as JSON dict.

    Args:
        result: CombinedResult from merger
        ruleset_map: Optional RulesetMap for accurate file counts
        project_root: Root to relativize regime keys against (defaults to cwd)
        file_type_by_path: Generic-scan file types, so surface_health routes @-imports
            to the Imported surface consistently with the text view

    Returns:
        Dict with findings, stats, compliance, tier, category info.
    """
    from dataclasses import asdict

    from reporails_cli.core.platform.runtime.merger import CombinedResult

    if not isinstance(result, CombinedResult):
        return {"error": "Invalid result type"}

    from reporails_cli.core.platform.policy.leverage import resolve_leverage
    from reporails_cli.formatters.text.display_constants import display_rule_id

    # Group findings by file for agent consumption — agents work file-by-file.
    # `leverage` is additive (raw `severity` is unchanged — the machine baseline).
    # It reflects the server's live per-finding tier when present, else the table.
    # `rule` is the canonical `<NS>:<CAT>:<SLOT>` id (same as text output); the raw
    # client-check token, when it differs, is preserved under `label` for baseline stability.
    by_file: dict[str, list[dict[str, Any]]] = {}
    for f in result.findings:
        canonical = display_rule_id(f.rule)
        entry: dict[str, Any] = {
            "line": f.line,
            "severity": f.severity,
            "rule": canonical,
            "category": _category_for_rule(canonical),
            "leverage": resolve_leverage(f).value,
            "message": f.message,
        }
        if canonical != f.rule:
            entry["label"] = f.rule
        if f.fix:
            entry["fix"] = f.fix
        by_file.setdefault(f.file, []).append(entry)

    regime_by_file = _regime_by_file(result, project_root or Path.cwd())
    data: dict[str, Any] = {
        "offline": result.offline,
        "tier": result.tier,
        "quality": float(result.quality.display_score) if result.quality is not None else None,
        "level": result.level.value,
        "files": {
            fp: _file_entry(findings, regime_by_file.get(fp))
            for fp, findings in sorted(by_file.items(), key=lambda x: -len(x[1]))
        },
        "stats": asdict(result.stats),
    }
    if result.cross_file:
        data["cross_file"] = [
            {
                "file_1": cf.file_1,
                "file_2": cf.file_2,
                "line_1": cf.line_1,
                "line_2": cf.line_2,
                "type": cf.finding_type,
            }
            for cf in result.cross_file
        ]
    if result.hints:
        data["pro"] = _pro_summary(result.hints)
    if result.cross_file_coordinates:
        data["cross_file_coordinates"] = [
            {
                "file_1": c.file_1,
                "file_2": c.file_2,
                "type": c.finding_type,
                "count": c.count,
            }
            for c in result.cross_file_coordinates
        ]
    from reporails_cli.formatters.text.scorecard import compute_surface_scores

    surfaces = compute_surface_scores(
        result, ruleset_map=ruleset_map, project_root=project_root or Path.cwd(), file_type_by_path=file_type_by_path
    )
    if surfaces:
        data["surface_health"] = [
            {
                "name": s.name,
                "score": s.score,
                "file_count": s.file_count,
                "finding_count": s.finding_count,
                "category_breakdown": dict(s.category_breakdown),
            }
            for s in surfaces
        ]
    data["top_rules"] = _aggregate_top_rules(result.findings)
    return data


def _aggregate_top_rules(findings: Any, limit: int = 10) -> list[dict[str, Any]]:
    """Group findings by rule and return the top `limit` by count.

    Each entry: `{"rule": "<id>", "count": <int>, "severity": "<worst>"}`.
    Severity is the worst (error > warning > info) seen for that rule.
    Used by both the JSON envelope and the text scorecard so the
    aggregation has one source of truth.
    """
    from reporails_cli.formatters.text.display_constants import display_rule_id

    severity_rank = {"error": 0, "warning": 1, "info": 2}
    buckets: dict[str, dict[str, Any]] = {}
    for f in findings:
        rule = display_rule_id(f.rule)
        bucket = buckets.setdefault(rule, {"count": 0, "severity": f.severity})
        bucket["count"] += 1
        if severity_rank.get(f.severity, 3) < severity_rank.get(bucket["severity"], 3):
            bucket["severity"] = f.severity
    ordered = sorted(
        ({"rule": rule, "count": b["count"], "severity": b["severity"]} for rule, b in buckets.items()),
        key=lambda r: (-r["count"], r["rule"]),
    )
    return ordered[:limit]
