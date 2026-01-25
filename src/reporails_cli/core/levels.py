"""Level configuration and rule-to-level mapping.

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
    Level.L1: "Absent",
    Level.L2: "Basic",
    Level.L3: "Structured",
    Level.L4: "Abstracted",
    Level.L5: "Governed",
    Level.L6: "Adaptive",
}


@lru_cache(maxsize=1)
def get_level_config() -> dict[str, Any]:
    """Load bundled levels.yml configuration.

    Cached for performance.

    Returns:
        Parsed levels.yml content
    """
    levels_path = get_levels_path()
    if not levels_path.exists():
        return {"levels": {}, "score_thresholds": {}, "detection": {}}

    content = levels_path.read_text(encoding="utf-8")
    config: dict[str, Any] = yaml.safe_load(content) or {}
    return config


def get_rules_for_level(level: Level) -> set[str]:
    """Get all rule IDs required for a given level.

    Includes rules from all levels up to and including the given level.

    Args:
        level: Target capability level

    Returns:
        Set of rule IDs applicable at this level
    """
    config = get_level_config()
    levels_data = config.get("levels", {})

    # Build rules set by traversing level inheritance
    all_rules: set[str] = set()
    level_order = [Level.L1, Level.L2, Level.L3, Level.L4, Level.L5, Level.L6]
    target_index = level_order.index(level)

    for lvl in level_order[: target_index + 1]:
        level_key = lvl.value
        if level_key in levels_data:
            rules = levels_data[level_key].get("required_rules", [])
            all_rules.update(rules)

    return all_rules


def get_level_label(level: Level) -> str:
    """Get human-readable label for level.

    Args:
        level: Capability level

    Returns:
        Label string (e.g., "Abstracted")
    """
    return LEVEL_LABELS.get(level, "Unknown")


def get_level_includes(level: Level) -> list[Level]:
    """Get levels included by inheritance.

    Args:
        level: Target level

    Returns:
        List of included levels (lower levels)
    """
    config = get_level_config()
    levels_data = config.get("levels", {})

    level_key = level.value
    if level_key not in levels_data:
        return []

    includes = levels_data[level_key].get("includes", [])
    return [Level(inc) for inc in includes if inc in [lv.value for lv in Level]]


def get_score_threshold(level: Level) -> int:
    """Get capability score threshold for a level.

    Args:
        level: Target level

    Returns:
        Minimum score required for this level
    """
    config = get_level_config()
    thresholds = config.get("score_thresholds", {})
    result = thresholds.get(level.value, 0)
    return int(result)


def capability_score_to_level(score: int) -> Level:
    """Map capability score to level.

    Args:
        score: Capability score (0-12)

    Returns:
        Corresponding level
    """
    config = get_level_config()
    thresholds = config.get("score_thresholds", {})

    # Default thresholds if not in config
    if not thresholds:
        thresholds = {"L1": 0, "L2": 1, "L3": 3, "L4": 5, "L5": 7, "L6": 10}

    # Find highest level where score meets threshold
    level_order = [Level.L6, Level.L5, Level.L4, Level.L3, Level.L2, Level.L1]
    for level in level_order:
        threshold = thresholds.get(level.value, 0)
        if score >= threshold:
            return level

    return Level.L1


def detect_orphan_features(features: DetectedFeatures, base_level: Level) -> bool:
    """Check if project has features from levels above base level.

    Example: L3 project with backbone.yml (L6 feature) → has_orphan = True
    Display as "L3+" to indicate advanced features present.

    Args:
        features: Detected project features
        base_level: Base capability level

    Returns:
        True if features above base level are present
    """
    level_features: dict[Level, list[bool]] = {
        Level.L6: [features.has_backbone],
        Level.L5: [features.component_count >= 3, features.has_shared_files],
        Level.L4: [features.has_rules_dir],
        Level.L3: [features.has_imports, features.has_multiple_instruction_files],
    }

    level_order = [Level.L1, Level.L2, Level.L3, Level.L4, Level.L5, Level.L6]
    base_index = level_order.index(base_level)

    # Check features from levels above base
    for level in level_order[base_index + 1 :]:
        if level in level_features and any(level_features[level]):
            return True

    return False
