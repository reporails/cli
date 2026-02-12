"""Semantic rule request building - creates JudgmentRequests for LLM evaluation.

Semantic rules require OpenGrep pattern matches before LLM evaluation.
No match = rule passes (nothing to evaluate).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.models import JudgmentRequest, Rule, RuleType, Severity
from reporails_cli.core.sarif import extract_rule_id, get_location


def build_request_from_sarif_result(
    rule: Rule,
    sarif_result: dict[str, Any],
    target: Path,
) -> JudgmentRequest | None:
    """Build a JudgmentRequest from a single SARIF result for a semantic rule.

    Args:
        rule: Semantic rule definition.
        sarif_result: Single SARIF result dict.
        target: Project root for snippet extraction.

    Returns:
        JudgmentRequest, or None if snippet missing or rule lacks required fields.
    """
    location = get_location(sarif_result)
    snippet = extract_snippet(sarif_result, target)
    if not snippet:
        return None
    return build_request(rule, snippet, location)


def build_semantic_requests(
    sarif: dict[str, Any],
    rules: dict[str, Rule],
    target: Path,
) -> list[JudgmentRequest]:
    requests: list[JudgmentRequest] = []
    semantic_rules = {k: v for k, v in rules.items() if v.type == RuleType.SEMANTIC}

    if not semantic_rules:
        return requests

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            sarif_rule_id = result.get("ruleId", "")
            rule_id = extract_rule_id(sarif_rule_id)

            rule = semantic_rules.get(rule_id)
            if not rule:
                continue

            request = build_request_from_sarif_result(rule, result, target)
            if request:
                requests.append(request)

    return requests


def extract_snippet(result: dict[str, Any], target: Path) -> str | None:
    """Extract matched content snippet from SARIF result.

    SARIF provides the matched region. Use that instead of reading whole file.
    Falls back to context lines around match if snippet not in SARIF.
    """
    # Try to get snippet from SARIF
    locations = result.get("locations", [])
    if locations:
        physical = locations[0].get("physicalLocation", {})
        region = physical.get("region", {})

        # SARIF may include the snippet directly
        snippet: str | None = region.get("snippet", {}).get("text")
        if snippet:
            return snippet

    # Fallback: read lines around the match
    location = get_location(result)
    if ":" not in location:
        return None

    file_path, line_str = location.rsplit(":", 1)
    try:
        line_num = int(line_str)
    except ValueError:
        return None

    full_path = target / file_path
    try:
        lines = full_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None

    # Get 5 lines of context (2 before, match, 2 after)
    start = max(0, line_num - 3)
    end = min(len(lines), line_num + 2)
    context_lines = lines[start:end]

    return "\n".join(context_lines)


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
