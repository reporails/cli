"""Scoring functions for reporails. All pure functions."""

from __future__ import annotations

from reporails_cli.core.models import FrictionEstimate, Level, Severity, Violation

# Severity weights for scoring (higher = more impact)
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 5.5,
    Severity.HIGH: 4.0,
    Severity.MEDIUM: 2.5,
    Severity.LOW: 1.0,
}

# Default weight for rules (used when calculating total possible points)
DEFAULT_RULE_WEIGHT: float = 2.5

# Level labels - must match levels.yml
LEVEL_LABELS: dict[Level, str] = {
    Level.L1: "Absent",
    Level.L2: "Basic",
    Level.L3: "Structured",
    Level.L4: "Abstracted",
    Level.L5: "Governed",
    Level.L6: "Adaptive",
}


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


def calculate_score(rules_checked: int, violations: list[Violation]) -> float:
    """Calculate display score on 0-10 scale.

    Score = (earned_points / possible_points) × 10

    Lost points are capped per rule - multiple violations of the same rule
    don't deduct more than the rule's weight (DEFAULT_RULE_WEIGHT).

    Args:
        rules_checked: Total number of rules checked
        violations: List of violations found

    Returns:
        Score between 0.0 and 10.0
    """
    if rules_checked == 0:
        return 10.0  # No rules = perfect

    # Total possible points
    possible = rules_checked * DEFAULT_RULE_WEIGHT

    # Group violations by rule_id, cap lost points per rule
    unique_violations = dedupe_violations(violations)
    by_rule: dict[str, float] = {}
    for v in unique_violations:
        weight = SEVERITY_WEIGHTS.get(v.severity, DEFAULT_RULE_WEIGHT)
        # Accumulate but cap at rule weight
        current = by_rule.get(v.rule_id, 0.0)
        by_rule[v.rule_id] = min(current + weight, DEFAULT_RULE_WEIGHT)

    lost = sum(by_rule.values())

    # Earned = possible - lost (floor at 0)
    earned = max(0.0, possible - lost)

    # Score on 0-10 scale
    score = (earned / possible) * 10
    return round(score, 1)


def get_severity_weight(severity: Severity) -> float:
    """Get weight for a severity level.

    Args:
        severity: Severity level

    Returns:
        Weight value
    """
    return SEVERITY_WEIGHTS.get(severity, DEFAULT_RULE_WEIGHT)


def estimate_friction(violations: list[Violation]) -> FrictionEstimate:
    """Estimate friction from violations.

    Friction levels based on violation severity:
    - extreme: Any critical violation
    - high: 2+ high severity OR 5+ total violations
    - medium: 1 high severity OR 3-4 violations
    - small: 1-2 violations (medium/low severity)
    - none: No violations

    Args:
        violations: List of violations

    Returns:
        FrictionEstimate with level
    """
    unique = dedupe_violations(violations)

    if not unique:
        return FrictionEstimate(level="none")

    # Count by severity
    critical_count = sum(1 for v in unique if v.severity == Severity.CRITICAL)
    high_count = sum(1 for v in unique if v.severity == Severity.HIGH)
    total_count = len(unique)

    # Determine level
    if critical_count > 0:
        level = "extreme"
    elif high_count >= 2 or total_count >= 5:
        level = "high"
    elif high_count >= 1 or total_count >= 3:
        level = "medium"
    else:
        level = "small"

    return FrictionEstimate(level=level)


def get_level_label(level: Level) -> str:
    """Get human-readable label for level.

    Args:
        level: Maturity level

    Returns:
        Label string (e.g., "Abstracted")
    """
    return LEVEL_LABELS.get(level, "Unknown")


def has_critical_violations(violations: list[Violation]) -> bool:
    """Check if any violation is critical.

    Args:
        violations: List of violations

    Returns:
        True if any violation has CRITICAL severity
    """
    return any(v.severity == Severity.CRITICAL for v in violations)


# Legacy compatibility
def get_severity_points(severity: Severity) -> int:
    """Legacy: Get point deduction for a severity level."""
    points_map = {
        Severity.CRITICAL: -25,
        Severity.HIGH: -15,
        Severity.MEDIUM: -10,
        Severity.LOW: -5,
    }
    return points_map.get(severity, -5)
