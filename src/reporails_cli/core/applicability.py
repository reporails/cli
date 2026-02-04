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
        except (OSError, RuntimeError) as exc:
            if isinstance(exc, RuntimeError) or getattr(exc, "errno", None) == errno.ELOOP:
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

    # Check for abstracted structure (rules, skills, agents directories)
    abstracted_dirs = [
        ".claude/rules",
        ".claude/skills",
        ".claude/agents",
        ".cursor/rules",
        ".ai/rules",
    ]
    for dirname in abstracted_dirs:
        d = target / dirname
        if d.exists() and any(d.iterdir()):
            features.is_abstracted = True
            break

    # Check for backbone.yml
    backbone_path = target / ".reporails" / "backbone.yml"
    features.has_backbone = backbone_path.exists()

    # Count instruction files (all agents, not just CLAUDE.md)
    all_instruction_files = get_all_instruction_files(target)
    features.instruction_file_count = len(all_instruction_files)
    features.has_multiple_instruction_files = len(all_instruction_files) > 1

    if features.instruction_file_count > 0:
        features.has_instruction_file = True

    # Check for hierarchical structure: any agent with the same instruction
    # file name appearing at multiple directory levels (e.g. root CLAUDE.md
    # + nested src/CLAUDE.md).  Driven by detect_agents(), not hardcoded names.
    from reporails_cli.core.agents import detect_agents

    for detected in detect_agents(target):
        names_at_root: set[str] = set()
        has_nested = False
        for f in detected.instruction_files:
            if f.parent == target:
                names_at_root.add(f.name)
            else:
                has_nested = True
        if names_at_root and has_nested:
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


# Legacy alias for backward compatibility
def detect_features(target: Path) -> DetectedFeatures:
    """Legacy alias for detect_features_filesystem()."""
    return detect_features_filesystem(target)
