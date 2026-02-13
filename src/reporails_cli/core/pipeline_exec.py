"""Pipeline execution — per-rule ordered check dispatch.

Consumes PipelineState from pipeline.py. Handles mechanical dispatch,
deterministic SARIF consumption, negation, semantic short-circuit,
and annotation propagation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from reporails_cli.core.mechanical.runner import (
    bind_instruction_files,
    dispatch_single_check,
    resolve_location,
)
from reporails_cli.core.models import (
    Check,
    JudgmentRequest,
    Rule,
    Violation,
)
from reporails_cli.core.pipeline import BLOCKING_CHECKS, CEILING, PipelineState
from reporails_cli.core.sarif import extract_check_id, get_location, get_severity
from reporails_cli.core.semantic import build_request_from_sarif_result

logger = logging.getLogger(__name__)


def execute_rule_checks(  # pylint: disable=too-many-arguments
    rule: Rule,
    state: PipelineState,
    scan_root: Path,
    template_vars: dict[str, str | list[str]],
    instruction_files: list[Path] | None,
) -> list[JudgmentRequest]:
    """Execute a rule's ordered check sequence against pipeline state.

    Walks rule.checks in order. For each check:
    - Verifies check.type is allowed by rule.type ceiling
    - mechanical: dispatches via dispatch_single_check, handles blocking/annotations
    - deterministic: reads from state._sarif_by_rule, converts to violations
    - semantic: short-circuits if no candidates, else builds JudgmentRequest

    Returns:
        List of JudgmentRequests for semantic checks (may be empty).
    """
    allowed = CEILING.get(rule.type)
    if allowed is None:
        logger.warning("Unknown rule type '%s' for rule %s, skipping all checks", rule.type, rule.id)
        return []
    effective_vars = bind_instruction_files(template_vars, scan_root, instruction_files)
    location = resolve_location(scan_root, rule, effective_vars)
    judgment_requests: list[JudgmentRequest] = []
    det_candidate_count = 0

    for check in rule.checks:
        if check.type not in allowed:
            logger.warning(
                "Check type '%s' exceeds ceiling for rule type '%s' (rule %s), skipping",
                check.type,
                rule.type.value,
                rule.id,
            )
            continue

        if check.type == "mechanical":
            _handle_mechanical(check, rule, state, scan_root, effective_vars, location)
        elif check.type == "deterministic":
            det_candidate_count += _handle_deterministic(check, rule, state, effective_vars, scan_root)
        elif check.type == "semantic":
            _handle_semantic(rule, state, scan_root, det_candidate_count, judgment_requests)

    return judgment_requests


def _handle_mechanical(
    check: Check,
    rule: Rule,
    state: PipelineState,
    scan_root: Path,
    effective_vars: dict[str, str | list[str]],
    location: str,
) -> None:
    """Process a mechanical check within per-rule iteration."""
    violation, raw_result = dispatch_single_check(check, rule, scan_root, effective_vars, location)

    if violation:
        state.findings.append(violation)
        if check.check in BLOCKING_CHECKS:
            loc_path = violation.location.rsplit(":", 1)[0] if ":" in violation.location else "."
            state.exclude_target(loc_path, check.check or "unknown")

    if raw_result and raw_result.annotations:
        _propagate_annotations(raw_result.annotations, state, location)


def _handle_deterministic(
    check: Check,
    rule: Rule,
    state: PipelineState,
    template_vars: dict[str, str | list[str]],
    scan_root: Path,
) -> int:
    """Process a deterministic check. Returns candidate count."""
    sarif_results = state.get_rule_sarif(rule.id)
    check_results = _filter_sarif_for_check(sarif_results, check)

    if check.negate:
        _handle_negated_deterministic(check, rule, state, check_results, template_vars, scan_root)
        return 0

    for result in check_results:
        location = get_location(result)
        sarif_rule_id = result.get("ruleId", "")
        check_id = extract_check_id(sarif_rule_id)
        severity = get_severity(rule, check_id)
        message = result.get("message", {}).get("text", "")
        state.findings.append(
            Violation(
                rule_id=rule.id,
                rule_title=rule.title,
                location=location,
                message=message,
                severity=severity,
                check_id=check_id,
            )
        )

    return len(check_results)


def _handle_negated_deterministic(
    check: Check,
    rule: Rule,
    state: PipelineState,
    check_results: list[dict[str, Any]],
    template_vars: dict[str, str | list[str]],
    scan_root: Path,
) -> None:
    """Handle negated deterministic check (finding = pass, no finding = violation)."""
    if check_results:
        return  # Content found -> pass

    location = resolve_location(scan_root, rule, template_vars)

    state.findings.append(
        Violation(
            rule_id=rule.id,
            rule_title=rule.title,
            location=location,
            message="Expected content not found",
            severity=check.severity,
            check_id=":".join(check.id.split(":")[3:]) if check.id.count(":") >= 4 else check.id,
        )
    )


def _handle_semantic(
    rule: Rule,
    state: PipelineState,
    scan_root: Path,
    det_candidate_count: int,
    judgment_requests: list[JudgmentRequest],
) -> None:
    """Process a semantic check within per-rule iteration."""
    sarif_results = state.get_rule_sarif(rule.id)
    if not sarif_results and det_candidate_count == 0:
        return  # Short-circuit: no candidates -> semantic never fires

    for result in sarif_results:
        request = build_request_from_sarif_result(rule, result, scan_root)
        if request:
            judgment_requests.append(request)


def _filter_sarif_for_check(
    sarif_results: list[dict[str, Any]],
    check: Check,
) -> list[dict[str, Any]]:
    """Filter SARIF results to those matching a specific check by ID suffix."""
    if not sarif_results:
        return []

    parts = check.id.split(":")
    if len(parts) >= 5:
        expected_suffix = ":".join(parts[3:])
    else:
        # Rule-level check (no suffix) — return all results for this rule
        return list(sarif_results)

    matched = []
    for result in sarif_results:
        sarif_rule_id = result.get("ruleId", "")
        check_id = extract_check_id(sarif_rule_id)
        if check_id == expected_suffix:
            matched.append(result)
    return matched


def _propagate_annotations(
    annotations: dict[str, Any],
    state: PipelineState,
    location: str,
) -> None:
    """Propagate check result annotations to pipeline state."""
    loc_path = location.rsplit(":", 1)[0] if ":" in location else "."
    for key, value in annotations.items():
        state.annotate_target(loc_path, key, value)
