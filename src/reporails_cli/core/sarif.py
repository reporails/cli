"""SARIF parsing - converts OpenGrep output to domain objects.

All functions are pure (no I/O).
"""

from __future__ import annotations

import re
from typing import Any

from reporails_cli.core.models import Rule, Severity, Violation

# Matches the start of a rule coordinate: NAMESPACE.CATEGORY.SLOT
# Namespace: uppercase letters + optional underscore (CORE, CLAUDE, RRAILS_CLAUDE, etc.)
# Category: single uppercase letter (S, C, E, M, G)
# Slot: exactly 4 digits
_COORDINATE_RE = re.compile(r"^[A-Z][A-Z_]*\.[A-Z]\.\d{4}")


def _find_coordinate_start(parts: list[str]) -> int:
    """Find the index where the rule coordinate starts in dot-split parts.

    OpenGrep may prefix the rule ID with temp directory path components
    when template-resolved yml files are used (e.g., tmp.tmpXXXXXX.CORE.S.0001...).
    This function locates the actual coordinate start by matching the
    NAMESPACE.CATEGORY.SLOT pattern.

    Args:
        parts: Dot-split segments of the SARIF ruleId

    Returns:
        Index of the first coordinate segment, or 0 if no prefix detected
    """
    for i in range(len(parts) - 2):
        candidate = ".".join(parts[i : i + 3])
        if _COORDINATE_RE.match(candidate):
            return i
    return 0


def extract_rule_id(sarif_rule_id: str) -> str:
    """Extract rule coordinate from SARIF ruleId.

    OpenGrep rule IDs use dots (colons are invalid in OpenGrep IDs).
    Dot-format: REGISTRY.CATEGORY.SLOT.check.NNNN -> REGISTRY:CATEGORY:SLOT

    When template resolution writes yml to a temp directory, OpenGrep may
    prefix the ruleId with path components (e.g., tmp.tmpXXX.CORE.S.0001...).
    This function strips the prefix by locating the coordinate pattern.

    Example: CORE.S.0001.check.0001 -> CORE:S:0001
    Example: tmp.tmpXXX.CORE.S.0001.check.0001 -> CORE:S:0001
    Example: RRAILS_CLAUDE.S.0002.check.0001 -> RRAILS_CLAUDE:S:0002

    Args:
        sarif_rule_id: Full ruleId from SARIF output (dot-separated)

    Returns:
        Rule coordinate in colon format (e.g., CORE:S:0001)
    """
    parts = sarif_rule_id.split(".")
    start = _find_coordinate_start(parts)
    if start + 3 <= len(parts):
        return ":".join(parts[start : start + 3])
    return sarif_rule_id


def extract_check_id(sarif_rule_id: str) -> str | None:
    """Extract check ID suffix from SARIF ruleId.

    OpenGrep rule IDs use dots. Returns colon-format for internal use.
    Handles temp directory prefix in the same way as extract_rule_id.

    Example: CORE.S.0001.check.0001 -> check:0001
    Example: tmp.tmpXXX.CORE.S.0001.check.0001 -> check:0001

    Args:
        sarif_rule_id: Full ruleId from SARIF output (dot-separated)

    Returns:
        Check suffix in colon format (e.g., "check:0001") or None
    """
    parts = sarif_rule_id.split(".")
    start = _find_coordinate_start(parts)
    suffix_start = start + 3
    if suffix_start < len(parts):
        return ":".join(parts[suffix_start:])
    return None


def get_location(result: dict[str, Any]) -> str:
    """Extract location string from SARIF result.

    Args:
        result: SARIF result object

    Returns:
        Location string in format "file:line"
    """
    locations = result.get("locations", [])
    if not locations:
        return "unknown"

    loc = locations[0].get("physicalLocation", {})
    artifact = loc.get("artifactLocation", {}).get("uri", "unknown")
    region = loc.get("region", {})
    line = region.get("startLine", 0)
    return f"{artifact}:{line}"


def get_severity(rule: Rule | None, check_id: str | None) -> Severity:
    """Get severity for a violation.

    Looks up severity from rule's checks list by check ID suffix, falls back to MEDIUM.

    Args:
        rule: Rule object (may be None)
        check_id: Check ID suffix from SARIF (e.g., "check:0001")

    Returns:
        Severity level
    """
    if rule is None:
        return Severity.MEDIUM

    # Try to find matching check by ID suffix
    for check in rule.checks:
        if check_id and check.id.endswith(check_id):
            return check.severity

    # Fall back to first check's severity
    if rule.checks:
        return rule.checks[0].severity

    return Severity.MEDIUM


def parse_sarif(  # pylint: disable=too-many-locals
    sarif: dict[str, Any],
    rules: dict[str, Rule],
) -> list[Violation]:
    """Parse OpenGrep SARIF output into Violation objects."""
    violations = []

    for run in sarif.get("runs", []):
        # Build map of rule levels from tool definitions
        rule_levels: dict[str, str] = {}
        tool = run.get("tool", {}).get("driver", {})
        for rule_def in tool.get("rules", []):
            rule_id = rule_def.get("id", "")
            level = rule_def.get("defaultConfiguration", {}).get("level", "warning")
            rule_levels[rule_id] = level

        for result in run.get("results", []):
            sarif_rule_id = result.get("ruleId", "")

            # Skip INFO/note level findings
            rule_level = rule_levels.get(sarif_rule_id, "warning")
            if rule_level in ("note", "none"):
                continue

            rule_id = extract_rule_id(sarif_rule_id)
            check_id = extract_check_id(sarif_rule_id)
            message = result.get("message", {}).get("text", "")
            location = get_location(result)

            # Get rule metadata — skip results not in the provided rules dict
            rule = rules.get(rule_id)
            if rule is None:
                continue
            title = rule.title
            severity = get_severity(rule, check_id)

            violations.append(
                Violation(
                    rule_id=rule_id,
                    rule_title=title,
                    location=location,
                    message=message,
                    severity=severity,
                    check_id=check_id,
                )
            )

    return violations


def dedupe_violations(violations: list[Violation]) -> list[Violation]:
    """Deduplicate violations by (file, rule_id, check_id).

    Keeps first occurrence of each unique (file, rule_id, check_id) tuple.
    Multi-check rules produce distinct findings per check.

    Args:
        violations: List of violations (may have duplicates)

    Returns:
        Deduplicated list of violations
    """
    seen: set[tuple[str, str, str | None]] = set()
    result: list[Violation] = []

    for v in violations:
        file_path = v.location.rsplit(":", 1)[0] if ":" in v.location else v.location
        key = (file_path, v.rule_id, v.check_id)

        if key not in seen:
            seen.add(key)
            result.append(v)

    return result


def distribute_sarif_by_rule(
    sarif: dict[str, Any],
    rules: dict[str, Rule],
) -> dict[str, list[dict[str, Any]]]:
    """Group raw SARIF results by extracted rule_id.

    Iterates over all SARIF results, extracts the rule coordinate from each
    ruleId, and buckets results by rule_id. Only results whose rule_id appears
    in the provided rules dict are included.

    Args:
        sarif: Raw SARIF output from OpenGrep.
        rules: Dict of rules to filter by (rule_id -> Rule).

    Returns:
        Dict mapping rule_id to list of raw SARIF result dicts.
    """
    by_rule: dict[str, list[dict[str, Any]]] = {}

    for run in sarif.get("runs", []):
        # Build rule level lookup for INFO filtering
        rule_levels: dict[str, str] = {}
        tool = run.get("tool", {}).get("driver", {})
        for rule_def in tool.get("rules", []):
            rid = rule_def.get("id", "")
            level = rule_def.get("defaultConfiguration", {}).get("level", "warning")
            rule_levels[rid] = level

        for result in run.get("results", []):
            sarif_rule_id = result.get("ruleId", "")

            # Skip INFO/note level findings (same as parse_sarif)
            rule_level = rule_levels.get(sarif_rule_id, "warning")
            if rule_level in ("note", "none"):
                continue

            rule_id = extract_rule_id(sarif_rule_id)
            if rule_id not in rules:
                continue

            if rule_id not in by_rule:
                by_rule[rule_id] = []
            by_rule[rule_id].append(result)

    return by_rule
