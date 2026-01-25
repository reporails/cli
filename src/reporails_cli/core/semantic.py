"""Semantic rule request building - creates JudgmentRequests for LLM evaluation.

Semantic rules require OpenGrep pattern matches before LLM evaluation.
No match = rule passes (nothing to evaluate).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.models import JudgmentRequest, Rule, RuleType, Severity
from reporails_cli.core.sarif import extract_rule_id, get_location


def build_semantic_requests(
    sarif: dict[str, Any],
    rules: dict[str, Rule],
    target: Path,
) -> list[JudgmentRequest]:
    """Build JudgmentRequests only for files where patterns matched.

    Semantic rules MUST have OpenGrep patterns. This function only builds
    requests for locations where the pattern matched.

    Args:
        sarif: OpenGrep SARIF results for semantic patterns
        rules: Dict of semantic rules
        target: Project root directory (for reading matched files)

    Returns:
        List of JudgmentRequest objects for matched locations
    """
    requests: list[JudgmentRequest] = []

    # Get semantic rules only
    semantic_rules = {k: v for k, v in rules.items() if v.type == RuleType.SEMANTIC}

    if not semantic_rules:
        return requests

    # Process SARIF matches
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            sarif_rule_id = result.get("ruleId", "")
            rule_id = extract_rule_id(sarif_rule_id)
            location = get_location(result)

            rule = semantic_rules.get(rule_id)
            if not rule:
                continue

            # Read file content for this match
            file_path = location.rsplit(":", 1)[0] if ":" in location else location
            full_path = target / file_path

            try:
                content = full_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            request = build_request(rule, content, location)
            if request:
                requests.append(request)

    return requests


def build_request(
    rule: Rule,
    content: str,
    location: str,
) -> JudgmentRequest | None:
    """Build a single JudgmentRequest from a rule.

    Args:
        rule: Semantic rule definition
        content: File content to evaluate
        location: File path for location

    Returns:
        JudgmentRequest, or None if rule lacks required fields
    """
    if not rule.question:
        return None

    # Parse criteria
    criteria = _parse_criteria(rule.criteria)

    # Parse choices
    choices = _parse_choices(rule.choices)

    # Get examples
    examples = rule.examples or {"good": [], "bad": []}
    if not isinstance(examples, dict):
        examples = {"good": [], "bad": []}

    # Get pass value
    pass_value = rule.pass_value or "pass"

    # Get severity from first check, or default
    severity = Severity.MEDIUM
    if rule.checks:
        severity = rule.checks[0].severity

    return JudgmentRequest(
        rule_id=rule.id,
        rule_title=rule.title,
        content=content,
        location=location,
        question=rule.question,
        criteria=criteria,
        examples=examples,
        choices=choices,
        pass_value=pass_value,
        severity=severity,
        points_if_fail=-10,  # Default penalty
    )


def _parse_criteria(criteria: list[dict[str, str]] | str | None) -> dict[str, str]:
    """Parse criteria field to dict format.

    Args:
        criteria: Criteria in various formats

    Returns:
        Dict mapping criterion key to check description
    """
    if criteria is None:
        return {"pass_condition": "Evaluate based on context"}

    if isinstance(criteria, str):
        return {"pass_condition": criteria}

    if isinstance(criteria, list):
        result: dict[str, str] = {}
        for item in criteria:
            if isinstance(item, dict):
                key = item.get("key", f"criterion_{len(result)}")
                check = item.get("check", str(item))
                result[key] = check
        return result if result else {"pass_condition": "Evaluate based on context"}

    return {"pass_condition": "Evaluate based on context"}


def _parse_choices(choices: list[dict[str, str]] | list[str] | None) -> list[str]:
    """Parse choices field to list format.

    Args:
        choices: Choices in various formats

    Returns:
        List of choice values
    """
    if choices is None:
        return ["pass", "fail"]

    if not choices:
        return ["pass", "fail"]

    result: list[str] = []
    for choice in choices:
        if isinstance(choice, dict):
            value = choice.get("value", str(choice))
            result.append(str(value))
        else:
            result.append(str(choice))

    return result if result else ["pass", "fail"]
