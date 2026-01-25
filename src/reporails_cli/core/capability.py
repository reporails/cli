"""Capability detection - determines project capability level.

Two-phase detection:
1. Filesystem (applicability.py) - directory/file existence
2. Content (this module) - OpenGrep pattern matching
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.levels import capability_score_to_level, detect_orphan_features
from reporails_cli.core.models import (
    CapabilityResult,
    ContentFeatures,
    DetectedFeatures,
    Level,
)

# Capability weights for scoring
CAPABILITY_WEIGHTS: dict[str, int] = {
    "has_instruction_file": 1,
    "has_sections": 1,
    "has_imports": 1,
    "has_explicit_constraints": 1,
    "has_rules_dir": 2,
    "has_path_scoped_rules": 1,
    "has_shared_files": 1,
    "component_count_3plus": 1,
    "has_backbone": 2,
}
# Max: 12 points


def detect_features_content(sarif: dict[str, Any]) -> ContentFeatures:
    """Parse OpenGrep SARIF output to detect content features.

    Args:
        sarif: SARIF output from capability pattern detection

    Returns:
        ContentFeatures with detected flags
    """
    has_sections = False
    has_imports = False
    has_explicit_constraints = False
    has_path_scoped_rules = False

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")

            if "has-sections" in rule_id:
                has_sections = True
            elif "has-imports" in rule_id:
                has_imports = True
            elif "has-explicit-constraints" in rule_id:
                has_explicit_constraints = True
            elif "has-path-scoped-rules" in rule_id:
                has_path_scoped_rules = True

    return ContentFeatures(
        has_sections=has_sections,
        has_imports=has_imports,
        has_explicit_constraints=has_explicit_constraints,
        has_path_scoped_rules=has_path_scoped_rules,
    )


def calculate_capability_score(features: DetectedFeatures) -> int:
    """Calculate capability score from features.

    Args:
        features: Detected project features

    Returns:
        Score from 0 to 12
    """
    score = 0

    # Phase 1 features (filesystem)
    if features.has_instruction_file or features.has_claude_md:
        score += CAPABILITY_WEIGHTS["has_instruction_file"]
    if features.has_rules_dir:
        score += CAPABILITY_WEIGHTS["has_rules_dir"]
    if features.has_shared_files:
        score += CAPABILITY_WEIGHTS["has_shared_files"]
    if features.component_count >= 3:
        score += CAPABILITY_WEIGHTS["component_count_3plus"]
    if features.has_backbone:
        score += CAPABILITY_WEIGHTS["has_backbone"]

    # Phase 2 features (content)
    if features.has_sections:
        score += CAPABILITY_WEIGHTS["has_sections"]
    if features.has_imports:
        score += CAPABILITY_WEIGHTS["has_imports"]
    if features.has_explicit_constraints:
        score += CAPABILITY_WEIGHTS["has_explicit_constraints"]
    if features.has_path_scoped_rules:
        score += CAPABILITY_WEIGHTS["has_path_scoped_rules"]

    return score


def calculate_filesystem_score(features: DetectedFeatures) -> int:
    """Calculate capability score from filesystem features only.

    Used for early rule filtering before OpenGrep runs.
    Returns conservative estimate (may be lower than final level).

    Args:
        features: Detected project features (filesystem only)

    Returns:
        Score from 0 to 7 (filesystem features max)
    """
    score = 0

    if features.has_instruction_file or features.has_claude_md:
        score += CAPABILITY_WEIGHTS["has_instruction_file"]
    if features.has_rules_dir:
        score += CAPABILITY_WEIGHTS["has_rules_dir"]
    if features.has_shared_files:
        score += CAPABILITY_WEIGHTS["has_shared_files"]
    if features.component_count >= 3:
        score += CAPABILITY_WEIGHTS["component_count_3plus"]
    if features.has_backbone:
        score += CAPABILITY_WEIGHTS["has_backbone"]

    return score


def estimate_preliminary_level(features: DetectedFeatures) -> Level:
    """Estimate capability level from filesystem features only.

    Conservative estimate for early rule filtering.
    Final level is determined after content analysis.

    Args:
        features: Detected project features (filesystem only)

    Returns:
        Preliminary Level (may be lower than final)
    """
    from reporails_cli.core.levels import capability_score_to_level
    score = calculate_filesystem_score(features)
    return capability_score_to_level(score)


def merge_content_features(
    features: DetectedFeatures,
    content_features: ContentFeatures,
) -> DetectedFeatures:
    """Merge content features into main features object.

    Args:
        features: Base features from filesystem detection
        content_features: Features from content detection

    Returns:
        Updated DetectedFeatures
    """
    features.has_sections = content_features.has_sections
    features.has_imports = features.has_imports or content_features.has_imports
    features.has_explicit_constraints = content_features.has_explicit_constraints
    features.has_path_scoped_rules = content_features.has_path_scoped_rules
    return features


def determine_capability_level(
    features: DetectedFeatures,
    content_features: ContentFeatures | None = None,
) -> CapabilityResult:
    """Determine capability level from features.

    Two-phase pipeline:
    1. Filesystem features (already in features)
    2. Content features (merged in)

    Args:
        features: Detected project features
        content_features: Optional content features to merge

    Returns:
        CapabilityResult with level, score, and summary
    """
    # Merge content features if provided
    if content_features:
        merge_content_features(features, content_features)

    # Calculate score and level
    score = calculate_capability_score(features)
    level = capability_score_to_level(score)

    # Check for orphan features
    has_orphan = detect_orphan_features(features, level)

    # Generate summary
    summary = get_feature_summary(features)

    return CapabilityResult(
        features=features,
        capability_score=score,
        level=level,
        has_orphan_features=has_orphan,
        feature_summary=summary,
    )


def get_feature_summary(features: DetectedFeatures) -> str:
    """Generate human-readable summary of detected features.

    Args:
        features: Detected project features

    Returns:
        Summary string for display
    """
    parts = []

    # File count
    file_count = features.instruction_file_count
    if file_count == 0:
        parts.append("No instruction files")
    elif file_count == 1:
        parts.append("1 instruction file")
    else:
        parts.append(f"{file_count} instruction files")

    # Features present
    feature_list = []
    if features.has_rules_dir:
        feature_list.append(".claude/rules/")
    if features.has_backbone:
        feature_list.append("backbone.yml")
    if features.has_shared_files:
        feature_list.append("shared files")
    if features.has_hierarchical_structure:
        feature_list.append("hierarchical")

    if feature_list:
        parts.append(" + ".join(feature_list))

    return ", ".join(parts) if parts else "No features detected"
