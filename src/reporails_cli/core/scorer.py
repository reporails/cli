"""Scoring functions for reporails. All pure functions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from reporails_cli.core.models import Level, Severity, Violation

if TYPE_CHECKING:
    from reporails_cli.core.applicability import DetectedFeatures

# Severity weights for scoring (higher = more important)
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 5.5,
    Severity.HIGH: 4.0,
    Severity.MEDIUM: 2.5,
    Severity.LOW: 1.0,
}

# Default weight for rules (used when calculating total possible points)
DEFAULT_RULE_WEIGHT: float = 2.5

# Legacy: Severity point deductions (kept for backwards compatibility)
SEVERITY_POINTS: dict[Severity, int] = {
    Severity.CRITICAL: -25,
    Severity.HIGH: -15,
    Severity.MEDIUM: -10,
    Severity.LOW: -5,
}

# Level thresholds on 0-10 scale: (level, min_score, label)
# Score ranges: L1=0-3.9, L2=4-5.9, L3=6-6.9, L4=7-7.9, L5=8-8.9, L6=9-10
LEVEL_THRESHOLDS: list[tuple[Level, float, str]] = [
    (Level.L1, 0.0, "Absent"),
    (Level.L2, 4.0, "Minimal"),
    (Level.L3, 6.0, "Basic"),
    (Level.L4, 7.0, "Standard"),
    (Level.L5, 8.0, "Advanced"),
    (Level.L6, 9.0, "Governed"),
]

# Level labels for display
LEVEL_LABELS: dict[Level, str] = {
    Level.L1: "Absent",
    Level.L2: "Basic",
    Level.L3: "Structured",
    Level.L4: "Modular",
    Level.L5: "Governed",
    Level.L6: "Adaptive",
}

# Time waste by severity (minutes per violation per session)
# Conservative estimates - actual impact per session, not worst-case
SEVERITY_TIME_WASTE: dict[Severity, int] = {
    Severity.CRITICAL: 5,  # Clarification loop + partial redo
    Severity.HIGH: 3,  # Clarification loop
    Severity.MEDIUM: 2,  # Brief clarification
    Severity.LOW: 1,  # Minor friction
}


def calculate_weighted_score(
    rules_checked: int,
    violations: list[Violation],
) -> float:
    """
    Calculate weighted score on 0-10 scale.

    Score = (earned_points / possible_points) * 10

    - Each rule checked contributes to possible points (default weight)
    - Violations reduce earned points based on their severity weight
    - Higher severity = higher weight = more impact

    Args:
        rules_checked: Total number of rules checked
        violations: List of violations found

    Returns:
        Score between 0.0 and 10.0
    """
    if rules_checked == 0:
        return 10.0  # No rules = perfect

    # Total possible points (using default weight per rule)
    possible = rules_checked * DEFAULT_RULE_WEIGHT

    # Calculate points lost from violations (dedupe by rule_id per file)
    seen: set[tuple[str, str]] = set()
    lost = 0.0

    for v in violations:
        file_path = v.location.rsplit(":", 1)[0] if ":" in v.location else v.location
        key = (file_path, v.rule_id)

        if key in seen:
            continue
        seen.add(key)

        weight = SEVERITY_WEIGHTS.get(v.severity, DEFAULT_RULE_WEIGHT)
        lost += weight

    # Earned = possible - lost (floor at 0)
    earned = max(0.0, possible - lost)

    # Score on 0-10 scale
    score = (earned / possible) * 10
    return round(score, 1)


def calculate_score(rules_checked: int, violations: list[Violation]) -> float:
    """
    Calculate display score on 0-10 scale.

    Uses weighted scoring: passing rules earn points, violations lose points
    based on severity. Score reflects percentage of possible points earned.

    Args:
        rules_checked: Total number of rules checked
        violations: List of violations found

    Returns:
        Score between 0.0 and 10.0
    """
    return calculate_weighted_score(rules_checked, violations)


def has_critical_violations(violations: list[Violation]) -> bool:
    """
    Check if any violation is critical.

    Pure function.

    Args:
        violations: List of violations

    Returns:
        True if any violation has CRITICAL severity
    """
    return any(v.severity == Severity.CRITICAL for v in violations)


def determine_capability_level(features: DetectedFeatures | None) -> Level:
    """
    Determine capability level based on detected features.

    Capability levels describe what your setup enables, not quality.
    Level is determined purely by features present, not by score.

    Args:
        features: Detected project features, or None (defaults to L1)

    Returns:
        Capability level (L1-L6)
    """
    if features is None:
        return Level.L1

    # L6 requires backbone (YAML navigation map)
    if features.has_backbone:
        return Level.L6

    # L5 requires governance indicators (3+ components or shared files)
    if features.component_count >= 3 or features.has_shared_files:
        return Level.L5

    # L4 requires .claude/rules/
    if features.has_rules_dir:
        return Level.L4

    # L3 requires @imports or multiple instruction files
    if features.has_imports or features.has_multiple_instruction_files:
        return Level.L3

    # L2 requires CLAUDE.md exists
    if features.has_claude_md:
        return Level.L2

    return Level.L1


def get_next_level(current_level: Level) -> Level | None:
    """
    Get the next level above current.

    Args:
        current_level: Current capability level

    Returns:
        Next level, or None if already at L6
    """
    level_order = [Level.L1, Level.L2, Level.L3, Level.L4, Level.L5, Level.L6]
    current_idx = level_order.index(current_level)
    if current_idx < len(level_order) - 1:
        return level_order[current_idx + 1]
    return None


def get_level_min_score(level: Level) -> float:
    """
    Get minimum score required for a level.

    Args:
        level: Target level

    Returns:
        Minimum score on 0-10 scale
    """
    for lvl, min_score, _ in LEVEL_THRESHOLDS:
        if lvl == level:
            return min_score
    return 0.0


def estimate_time_waste(violations: list[Violation]) -> dict[str, int]:
    """
    Estimate time waste in minutes by category.

    Pure function. Dedupes by (file, rule_id) - same rule in same file
    only counts once for time waste calculation. Time is based on severity,
    not individual rules.

    Args:
        violations: List of violations

    Returns:
        Dict with 'total' and per-category (S, C, E, M, G) minutes
    """
    by_category: dict[str, int] = {}

    # Dedupe: only count first occurrence per (file, rule_id)
    seen: set[tuple[str, str]] = set()

    for v in violations:
        # Extract file from location (format: "path/file.md:line")
        file_path = v.location.rsplit(":", 1)[0] if ":" in v.location else v.location
        key = (file_path, v.rule_id)

        # Skip if already counted this rule in this file
        if key in seen:
            continue
        seen.add(key)

        # Time waste based on severity, not individual rule
        minutes = SEVERITY_TIME_WASTE.get(v.severity, 5)

        # Category is first character of rule_id (S, C, E, M, G)
        category = v.rule_id[0] if v.rule_id else "U"
        by_category[category] = by_category.get(category, 0) + minutes

    return {"total": sum(by_category.values()), **by_category}


def get_severity_points(severity: Severity) -> int:
    """
    Get point deduction for a severity level.

    Pure function.

    Args:
        severity: Severity level

    Returns:
        Negative points value
    """
    return SEVERITY_POINTS.get(severity, -5)


def get_level_label(level: Level) -> str:
    """
    Get human-readable label for level.

    Args:
        level: Maturity level

    Returns:
        Label string (e.g., "Standard")
    """
    return LEVEL_LABELS.get(level, "Unknown")
