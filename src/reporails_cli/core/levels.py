"""Level configuration and gate-based capability detection.

Loads from bundled levels.yml. All functions are pure after initial load.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, Any

import yaml

from reporails_cli.bundled import get_levels_path
from reporails_cli.core.models import Level

if TYPE_CHECKING:
    from reporails_cli.core.models import DetectedFeatures

# Level labels - must match levels.yml
LEVEL_LABELS: dict[Level, str] = {
    Level.L0: "Absent",
    Level.L1: "Basic",
    Level.L2: "Scoped",
    Level.L3: "Structured",
    Level.L4: "Abstracted",
    Level.L5: "Governed",
    Level.L6: "Adaptive",
}

# Gates that require OpenGrep content analysis (Phase 2)
CONTENT_GATES: frozenset[str] = frozenset({
    "has_sections",
    "has_explicit_constraints",
    "has_path_scoped_rules",
})

# Derived gates: computed from features rather than direct attribute access
DERIVED_GATES: dict[str, Any] = {
    "component_count_3plus": lambda f: f.component_count >= 3,
}

# Ordered levels for walking (L1 → L6)
_LEVEL_ORDER = [Level.L1, Level.L2, Level.L3, Level.L4, Level.L5, Level.L6]


@lru_cache(maxsize=1)
def get_level_config() -> dict[str, Any]:
    """Load bundled levels.yml configuration.

    Cached for performance.

    Returns:
        Parsed levels.yml content
    """
    levels_path = get_levels_path()
    if not levels_path.exists():
        return {"levels": {}}

    content = levels_path.read_text(encoding="utf-8")
    config: dict[str, Any] = yaml.safe_load(content) or {}
    return config


def get_rules_for_level(
    level: Level,
    extra_level_rules: dict[str, list[str]] | None = None,
) -> set[str]:
    """Get all rule IDs required for a given level.

    Includes rules from all levels up to and including the given level.

    Args:
        level: Target capability level
        extra_level_rules: Additional level→rule mappings (e.g., from packages)

    Returns:
        Set of rule IDs applicable at this level
    """
    config = get_level_config()
    levels_data = config.get("levels", {})

    # Build rules set by traversing level inheritance
    all_rules: set[str] = set()
    target_index = _LEVEL_ORDER.index(level)

    for lvl in _LEVEL_ORDER[: target_index + 1]:
        level_key = lvl.value
        if level_key in levels_data:
            rules = levels_data[level_key].get("rules", [])
            all_rules.update(rules)

    # Merge extra rules (from packages)
    if extra_level_rules:
        for lvl in _LEVEL_ORDER[: target_index + 1]:
            all_rules.update(extra_level_rules.get(lvl.value, []))

    return all_rules


def get_level_labels() -> dict[Level, str]:
    """Get all level labels."""
    return LEVEL_LABELS


def get_level_label(level: Level) -> str:
    """Get human-readable label for level.

    Args:
        level: Capability level

    Returns:
        Label string (e.g., "Abstracted")
    """
    return LEVEL_LABELS.get(level, "Unknown")


def _resolve_gate(features: DetectedFeatures, gate_name: str) -> bool:
    """Resolve a single gate name to a boolean.

    Checks derived gates first, then falls back to getattr on features.

    Args:
        features: Detected project features
        gate_name: Name of the gate to resolve

    Returns:
        True if the gate passes
    """
    if gate_name in DERIVED_GATES:
        return bool(DERIVED_GATES[gate_name](features))
    return bool(getattr(features, gate_name, False))


def _evaluate_gate_item(
    features: DetectedFeatures,
    item: str | list[str],
    skip_content: bool = False,
) -> bool:
    """Evaluate a single gate item from the detection config.

    - String: required gate (AND with siblings at the level)
    - List of strings: any-of gate (OR — at least one must pass)

    When skip_content=True, content-only gates are treated as passing
    (optimistic for preliminary estimation).

    Args:
        features: Detected project features
        item: Gate name (string) or list of gate names (OR group)
        skip_content: If True, treat content gates as passing

    Returns:
        True if the gate item passes
    """
    if isinstance(item, list):
        # OR group: at least one must pass
        return any(
            _evaluate_gate_item(features, sub, skip_content) for sub in item
        )

    # Single gate (string)
    if skip_content and item in CONTENT_GATES:
        return True
    return _resolve_gate(features, item)


def determine_level_from_gates(
    features: DetectedFeatures,
    skip_content: bool = False,
) -> Level:
    """Determine capability level by walking gates from L6 down to L1.

    A project is at the highest level where ALL gates for that level
    AND all levels below it pass. Gates are cumulative.

    Args:
        features: Detected project features
        skip_content: If True, content gates treated as passing (preliminary)

    Returns:
        Highest level where all cumulative gates pass
    """
    config = get_level_config()
    detection = config.get("detection", {})

    # Walk from L6 down to L1, find highest where all cumulative gates pass
    for level in reversed(_LEVEL_ORDER):
        if _all_cumulative_gates_pass(features, level, detection, skip_content):
            return level

    return Level.L0


def _all_cumulative_gates_pass(
    features: DetectedFeatures,
    target_level: Level,
    detection: dict[str, Any],
    skip_content: bool,
) -> bool:
    """Check if all gates from L1 through target_level pass.

    Args:
        features: Detected project features
        target_level: Level to check up to
        detection: Detection config from levels.yml
        skip_content: If True, content gates treated as passing

    Returns:
        True if all cumulative gates pass
    """
    target_index = _LEVEL_ORDER.index(target_level)

    for lvl in _LEVEL_ORDER[: target_index + 1]:
        gate_items = detection.get(lvl.value, [])
        for item in gate_items:
            if not _evaluate_gate_item(features, item, skip_content):
                return False

    return True


def detect_orphan_features(features: DetectedFeatures, base_level: Level) -> bool:
    """Check if project has features from levels above base level.

    Reads gates from levels.yml config instead of hardcoded dict.
    Example: L3 project with backbone.yml (L6 feature) → has_orphan = True
    Display as "L3+" to indicate advanced features present.

    Args:
        features: Detected project features
        base_level: Base capability level

    Returns:
        True if features above base level are present
    """
    config = get_level_config()
    detection = config.get("detection", {})

    base_index = _LEVEL_ORDER.index(base_level)

    # Check gates from levels above base
    for level in _LEVEL_ORDER[base_index + 1 :]:
        gate_items = detection.get(level.value, [])
        for item in gate_items:
            if _any_gate_passes(features, item):
                return True

    return False


def _any_gate_passes(features: DetectedFeatures, item: str | list[str]) -> bool:
    """Check if any gate in an item passes (for orphan detection).

    Args:
        features: Detected project features
        item: Gate name or OR group

    Returns:
        True if any gate passes
    """
    if isinstance(item, list):
        return any(_resolve_gate(features, sub) for sub in item)
    return _resolve_gate(features, item)
