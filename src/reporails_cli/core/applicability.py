"""Feature detection (filesystem) and rule applicability.

Phase 1 of capability detection - scans filesystem for features.
Phase 2 (content detection) is in capability.py.
"""

from __future__ import annotations

import errno
import logging
from pathlib import Path

import yaml

from reporails_cli.core.agents import get_all_instruction_files
from reporails_cli.core.levels import get_rules_for_level
from reporails_cli.core.models import DetectedFeatures, Level, Rule

logger = logging.getLogger(__name__)


def _count_components(backbone_data: dict) -> int:  # type: ignore[type-arg]
    """Count components from backbone data, version-aware.

    v1: count entries in components dict
    v2: count agents + their directory entries
    """
    version = backbone_data.get("version", 1)
    if version == 1:
        return len(backbone_data.get("components", {}))
    # v2: count agents + their directory entries
    agents = backbone_data.get("agents", {})
    count = 0
    for agent_data in agents.values():
        count += 1  # the agent itself
        for value in agent_data.values():
            if isinstance(value, str) and value.endswith("/"):
                count += 1
    return count


def resolve_symlinked_files(target: Path) -> list[Path]:
    """Find instruction files that are symlinks pointing outside the scan directory.

    OpenGrep skips symlinks whose resolved target is outside the scan directory.
    This function detects those files so their resolved paths can be passed as
    additional scan targets.

    Args:
        target: Project root path

    Returns:
        List of resolved (real) paths for symlinks pointing outside target
    """
    resolved: list[Path] = []
    try:
        real_target = target.resolve()
    except OSError:
        return resolved

    for path in get_all_instruction_files(target):
        if not path.is_symlink():
            continue
        try:
            real_path = path.resolve(strict=True)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                logger.warning(
                    "Circular symlink detected: %s — file will be skipped",
                    path,
                )
            continue
        # Only include if resolved path is outside the scan directory
        try:
            real_path.relative_to(real_target)
        except ValueError:
            # Outside the scan directory — OpenGrep will miss this
            resolved.append(real_path)

    return resolved


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
            features.component_count = _count_components(backbone_data)
        except (yaml.YAMLError, OSError):
            pass

    # Resolve symlinked instruction files (for OpenGrep extra targets)
    features.resolved_symlinks = resolve_symlinked_files(target)

    return features


def get_applicable_rules(
    rules: dict[str, Rule],
    level: Level,
    extra_level_rules: dict[str, list[str]] | None = None,
) -> dict[str, Rule]:
    """Filter rules to those applicable at the given level.

    Rules apply at their minimum level and above.

    Args:
        rules: Dict of all rules
        level: Detected capability level
        extra_level_rules: Additional level→rule mappings (e.g., from packages)

    Returns:
        Dict of applicable rules
    """
    # Get rule IDs for this level from levels.yml (+ package extras)
    applicable_ids = get_rules_for_level(level, extra_level_rules)

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
