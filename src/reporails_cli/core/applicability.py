"""Feature detection (filesystem) and rule applicability.

Phase 1 of capability detection - scans filesystem for features.
Phase 2 (content detection) is in capability.py.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from reporails_cli.core.levels import get_rules_for_level
from reporails_cli.core.models import DetectedFeatures, Level, Rule


def detect_features_filesystem(target: Path) -> DetectedFeatures:
    """Detect project features from file structure.

    Phase 1 of capability detection - filesystem only, no content analysis.

    Args:
        target: Project root path

    Returns:
        DetectedFeatures with filesystem-based indicators
    """
    features = DetectedFeatures()

    # Check for CLAUDE.md at root
    root_claude = target / "CLAUDE.md"
    features.has_claude_md = root_claude.exists()
    features.has_instruction_file = features.has_claude_md

    # Check for .claude/rules/
    rules_dir = target / ".claude" / "rules"
    features.has_rules_dir = rules_dir.exists() and any(rules_dir.glob("*.md"))

    # Check for other agent rules directories
    other_rules = [".cursor/rules", ".ai/rules"]
    for pattern in other_rules:
        other_dir = target / pattern
        if other_dir.exists() and any(other_dir.glob("*.md")):
            features.has_rules_dir = True
            break

    # Check for backbone.yml
    backbone_path = target / ".reporails" / "backbone.yml"
    features.has_backbone = backbone_path.exists()

    # Count instruction files
    claude_files = list(target.rglob("CLAUDE.md"))
    features.instruction_file_count = len(claude_files)
    features.has_multiple_instruction_files = len(claude_files) > 1

    if features.instruction_file_count > 0:
        features.has_instruction_file = True

    # Check for hierarchical structure (nested CLAUDE.md)
    for cf in claude_files:
        if cf.parent != target:
            features.has_hierarchical_structure = True
            break

    # Check for @imports in content (simple check, full check in Phase 2)
    if features.has_claude_md:
        try:
            content = root_claude.read_text(encoding="utf-8")
            features.has_imports = "@" in content
        except (OSError, UnicodeDecodeError):
            pass

    # Check for shared files
    shared_patterns = [".shared", "shared", ".ai/shared"]
    for pattern in shared_patterns:
        if (target / pattern).exists():
            features.has_shared_files = True
            break

    # Count components from backbone if present
    if features.has_backbone:
        try:
            backbone_content = backbone_path.read_text(encoding="utf-8")
            backbone_data = yaml.safe_load(backbone_content)
            features.component_count = len(backbone_data.get("components", {}))
        except (yaml.YAMLError, OSError):
            pass

    return features


def get_applicable_rules(rules: dict[str, Rule], level: Level) -> dict[str, Rule]:
    """Filter rules to those applicable at the given level.

    Rules apply at their minimum level and above.

    Args:
        rules: Dict of all rules
        level: Detected capability level

    Returns:
        Dict of applicable rules
    """
    # Get rule IDs for this level from levels.yml
    applicable_ids = get_rules_for_level(level)

    # Filter rules
    return {k: v for k, v in rules.items() if k in applicable_ids}


def get_feature_summary(features: DetectedFeatures) -> str:
    """Generate human-readable summary of detected features.

    Args:
        features: Detected project features

    Returns:
        Summary string for display
    """
    parts = []

    # File count
    if features.instruction_file_count == 0:
        parts.append("No instruction files")
    elif features.instruction_file_count == 1:
        parts.append("1 instruction file")
    else:
        parts.append(f"{features.instruction_file_count} instruction files")

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


# Legacy alias for backward compatibility
def detect_features(target: Path) -> DetectedFeatures:
    """Legacy alias for detect_features_filesystem()."""
    return detect_features_filesystem(target)
