"""SARIF parsing - converts OpenGrep output to domain objects.

All functions are pure (no I/O).
"""

from __future__ import annotations

import re
from typing import Any

from reporails_cli.core.models import Rule, Severity, Violation

# Severity weights for scoring
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 5.5,
    Severity.HIGH: 4.0,
    Severity.MEDIUM: 2.5,
    Severity.LOW: 1.0,
}


def extract_rule_id(sarif_rule_id: str) -> str:
    """Extract short rule ID from OpenGrep SARIF ruleId.

    OpenGrep formats rule IDs as: checks.{category}.{id}-{slug}
    Example: checks.structure.S1-many-h2-headings -> S1

    Handles prefixed IDs: AILS_E4, CLAUDE_S2, AILS_CLAUDE_M1

    Args:
        sarif_rule_id: Full ruleId from SARIF output

    Returns:
        Short rule ID (e.g., S1, C10, AILS_E4, CLAUDE_S2)
    """
    # Pattern: optional AILS_ and/or CLAUDE_ prefix, then letter + digits
    match = re.search(r"\.((?:AILS_)?(?:CLAUDE_)?[A-Z]\d+)-", sarif_rule_id)
    if match:
        return match.group(1)
    return sarif_rule_id


def extract_check_slug(sarif_rule_id: str) -> str | None:
    """Extract check slug from OpenGrep SARIF ruleId.

    OpenGrep formats rule IDs as: checks.{category}.{id}-{slug}
    Example: checks.structure.S1-many-sections -> many-sections

    Handles prefixed IDs: AILS_E4-slug, CLAUDE_S2-slug, AILS_CLAUDE_M1-slug

    Args:
        sarif_rule_id: Full ruleId from SARIF output

    Returns:
        Check slug (e.g., "many-sections") or None
    """
    match = re.search(r"\.(?:AILS_)?(?:CLAUDE_)?[A-Z]\d+-(.+)$", sarif_rule_id)
    if match:
        return match.group(1)
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


def get_severity(rule: Rule | None, check_slug: str | None) -> Severity:
    """Get severity for a violation.

    Looks up severity from rule's checks list, falls back to MEDIUM.

    Args:
        rule: Rule object (may be None)
        check_slug: Check slug from SARIF (may be None)

    Returns:
        Severity level
    """
    if rule is None:
        return Severity.MEDIUM

    # Try to find matching check
    for check in rule.checks:
        if check_slug and check_slug in check.id:
            return check.severity
        # Return first check's severity as default
        return check.severity

    return Severity.MEDIUM


def parse_sarif(sarif: dict[str, Any], rules: dict[str, Rule]) -> list[Violation]:
    """Parse OpenGrep SARIF output into Violation objects.

    Pure function — no I/O. Skips INFO/note level findings.

    Args:
        sarif: Parsed SARIF JSON
        rules: Dict of rules for metadata lookup

    Returns:
        List of Violation objects
    """
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

            short_rule_id = extract_rule_id(sarif_rule_id)
            check_slug = extract_check_slug(sarif_rule_id)
            message = result.get("message", {}).get("text", "")
            location = get_location(result)

            # Get rule metadata — skip results not in the provided rules dict
            rule = rules.get(short_rule_id)
            if rule is None:
                continue
            title = rule.title
            severity = get_severity(rule, check_slug)

            violations.append(
                Violation(
                    rule_id=short_rule_id,
                    rule_title=title,
                    location=location,
                    message=message,
                    severity=severity,
                    check_id=check_slug,
                )
            )

    return violations


def dedupe_violations(violations: list[Violation]) -> list[Violation]:
    """Deduplicate violations by (file, rule_id).

    Keeps first occurrence of each unique (file, rule_id) pair.

    Args:
        violations: List of violations (may have duplicates)

    Returns:
        Deduplicated list of violations
    """
    seen: set[tuple[str, str]] = set()
    result: list[Violation] = []

    for v in violations:
        file_path = v.location.rsplit(":", 1)[0] if ":" in v.location else v.location
        key = (file_path, v.rule_id)

        if key not in seen:
            seen.add(key)
            result.append(v)

    return result
