"""Capability detection - determines project capability level.

Two-phase detection:
1. Filesystem (applicability.py) - directory/file existence
2. Content (this module) - regex pattern matching
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.levels import detect_orphan_features, determine_level_from_gates
from reporails_cli.core.models import (
    CapabilityResult,
    ContentFeatures,
    DetectedFeatures,
    Level,
)


def detect_features_content(sarif: dict[str, Any]) -> ContentFeatures:
    """Parse SARIF output to detect content features.

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


def estimate_preliminary_level(features: DetectedFeatures) -> Level:
    """Estimate capability level from filesystem features only.

    Uses gate-based detection with skip_content=True, which treats
    content-only gates as passing (optimistic). This means slightly
    more rules loaded for regex Pass 2, never fewer.

    Args:
        features: Detected project features (filesystem only)

    Returns:
        Preliminary Level (may be higher than final)
    """
    return determine_level_from_gates(features, skip_content=True)


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
    """Determine capability level from features using gate-based detection.

    Two-phase pipeline:
    1. Filesystem features (already in features)
    2. Content features (merged in)

    Args:
        features: Detected project features
        content_features: Optional content features to merge

    Returns:
        CapabilityResult with level and summary
    """
    # Merge content features if provided
    if content_features:
        merge_content_features(features, content_features)

    # Determine level via gate walk
    level = determine_level_from_gates(features)

    # Check for orphan features
    has_orphan = detect_orphan_features(features, level)

    # Generate summary
    summary = get_feature_summary(features)

    return CapabilityResult(
        features=features,
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
    if features.is_abstracted:
        feature_list.append("abstracted")
    if features.has_backbone:
        feature_list.append("backbone.yml")
    if features.has_shared_files:
        feature_list.append("shared files")
    if features.has_hierarchical_structure:
        feature_list.append("hierarchical")

    if feature_list:
        parts.append(" + ".join(feature_list))

    return ", ".join(parts) if parts else "No features detected"
