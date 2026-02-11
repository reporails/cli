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
from reporails_cli.core.models import DetectedFeatures, Level, Rule

# Ordered levels for comparison (index = ordinal)
_LEVEL_ORDER = [Level.L0, Level.L1, Level.L2, Level.L3, Level.L4, Level.L5, Level.L6]

logger = logging.getLogger(__name__)


def _count_components(backbone_data: dict) -> int:  # type: ignore[type-arg]
    """Count distinct navigable areas declared in backbone."""
    version = backbone_data.get("version", 1)
    if version == 1:
        return len(backbone_data.get("components", {}))

    # v2+: collect distinct top-level directories from all path values
    top_dirs: set[str] = set()
    _collect_paths(backbone_data, top_dirs)
    return len(top_dirs)


def _collect_paths(data: object, top_dirs: set[str]) -> None:
    """Recursively extract top-level directories from backbone values."""
    if isinstance(data, dict):
        for value in data.values():
            _collect_paths(value, top_dirs)
    elif isinstance(data, list):
        for item in data:
            _collect_paths(item, top_dirs)
    elif isinstance(data, str) and "/" in data and ":" not in data and "@" not in data:
        # Extract top-level directory from path-like value (skip URLs)
        top = data.lstrip(".").lstrip("/").split("/")[0]
        if top:
            top_dirs.add(top)


def resolve_symlinked_files(target: Path) -> list[Path]:
    """Find instruction files that are symlinks pointing outside the scan directory."""
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


def _detect_l6_features(features: DetectedFeatures, target: Path) -> None:
    """Detect L6 features: skills directory, MCP config, memory directory."""
    # Check for skills directory (L6: dynamic_context)
    skills_dirs = [".claude/skills", ".cursor/skills"]
    for dirname in skills_dirs:
        d = target / dirname
        if d.exists() and any(d.iterdir()):
            features.has_skills_dir = True
            break

    # Check for MCP configuration (L6: extensibility)
    mcp_files = [".mcp.json", ".claude/mcp.json"]
    for fname in mcp_files:
        if (target / fname).exists():
            features.has_mcp_config = True
            break


def _detect_hierarchy_features(
    features: DetectedFeatures,
    target: Path,
) -> None:
    """Detect hierarchical structure from instruction files across directory levels."""
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

    # Check for hierarchical structure
    _detect_hierarchy_features(features, target)

    # Check for @imports and size control (simple checks, full in Phase 2)
    if features.has_claude_md:
        try:
            content = root_claude.read_text(encoding="utf-8")
            features.has_imports = "@" in content
            features.is_size_controlled = content.count("\n") < 500
        except (OSError, UnicodeDecodeError):
            pass
    elif features.has_instruction_file:
        # Non-Claude instruction file — assume size controlled
        features.is_size_controlled = True

    # Check for shared files
    shared_patterns = [".shared", "shared", ".ai/shared"]
    for pattern in shared_patterns:
        if (target / pattern).exists():
            features.has_shared_files = True
            break

    # L6 features: skills, MCP config
    _detect_l6_features(features, target)

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
) -> dict[str, Rule]:
    """Filter rules to those applicable at the given level.

    A rule applies when rule.level ≤ project_level (compared by ordinal).
    If rule A supersedes rule B, and both are applicable, drop B.

    Args:
        rules: Dict of all rules
        level: Detected capability level

    Returns:
        Dict of applicable rules
    """
    project_ordinal = _LEVEL_ORDER.index(level)

    # Filter by level ordinal
    applicable: dict[str, Rule] = {}
    for rule_id, rule in rules.items():
        try:
            rule_level = Level(rule.level)
        except ValueError:
            continue
        if _LEVEL_ORDER.index(rule_level) <= project_ordinal:
            applicable[rule_id] = rule

    # Handle supersession: if rule A supersedes rule B, drop B
    superseded_ids: set[str] = set()
    for rule in applicable.values():
        if rule.supersedes and rule.supersedes in applicable:
            superseded_ids.add(rule.supersedes)

    if superseded_ids:
        applicable = {k: v for k, v in applicable.items() if k not in superseded_ids}

    return applicable


def get_feature_summary(features: DetectedFeatures) -> str:
    """Generate human-readable summary of detected features."""
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
