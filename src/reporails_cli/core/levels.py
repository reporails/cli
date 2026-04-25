"""Level configuration and project level determination.

Two level mechanisms coexist:

1. Target existence (determine_project_level): computes present file types
   for rule applicability. Uses axis divergence from file type properties.

2. Capability gates (determine_level_from_gates): computes the displayed
   project level from detected features. Cumulative walk L1→L6, stop at
   first level with no detected capability.

The displayed level comes from (2). Rule applicability comes from (1).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.models import Level

if TYPE_CHECKING:
    from reporails_cli.core.models import ClassifiedFile, FileTypeDeclaration
    from reporails_cli.core.results import DetectedFeatures

# Level labels — canonical mapping (must match framework registry/levels.yml)
LEVEL_LABELS: dict[Level, str] = {
    Level.L0: "Absent",
    Level.L1: "Present",
    Level.L2: "Structured",
    Level.L3: "Substantive",
    Level.L4: "Actionable",
    Level.L5: "Refined",
    Level.L6: "Adaptive",
}

# Ordered levels for walking (L1 → L6)
_LEVEL_ORDER = [Level.L1, Level.L2, Level.L3, Level.L4, Level.L5, Level.L6]


def get_level_labels() -> dict[Level, str]:
    """Get all level labels."""
    return LEVEL_LABELS


# ===========================================================================
# Mechanism 1: Target existence (for rule applicability)
# ===========================================================================

# Baseline property values — "main" instruction file defaults.
# All 8 axes from the instruction file property space.
# Properties that match these contribute zero depth.
_BASELINE: dict[str, str] = {
    "format": "freeform",
    "scope": "global",
    "cardinality": "singleton",
    "loading": "session_start",
    "precedence": "project",
    "lifecycle": "static",
    "maintainer": "human",
    "vcs": "committed",
}


def _property_depth(properties: dict[str, str | list[str]]) -> int:
    """Count how many structural properties diverge from baseline.

    A list-valued property (e.g., format: [frontmatter, freeform]) diverges
    if it contains values beyond the baseline — the extra values represent
    additional structural complexity.
    """
    count = 0
    for prop, base in _BASELINE.items():
        actual = properties.get(prop, base)
        if isinstance(actual, list):
            # Diverges if the list contains any non-baseline value
            count += 1 if any(v != base for v in actual) else 0
        elif actual != base:
            count += 1
    return count


def determine_project_level(
    scan_root: Path,
    file_types: list[FileTypeDeclaration],
    classified_files: list[ClassifiedFile],
) -> tuple[Level, set[str]]:
    """Determine present file types for rule applicability.

    Returns (level_from_divergence, set of present file type names).
    The level value is NOT used for display — only present_types matters.
    """
    present: set[str] = set()
    max_depth = 0

    # Types already matched to actual files
    for cf in classified_files:
        present.add(cf.file_type)
        max_depth = max(max_depth, _property_depth(cf.properties))

    # Types declared but not yet in classified_files (check filesystem)
    for ft in file_types:
        if ft.name not in present and _type_exists(scan_root, ft.patterns):
            present.add(ft.name)
            max_depth = max(max_depth, _property_depth(ft.properties))

    if not present:
        return Level.L0, present

    return Level(f"L{min(max_depth + 1, 6)}"), present


def _type_exists(scan_root: Path, patterns: tuple[str, ...]) -> bool:
    """Check if any file matching the patterns exists under scan_root."""
    for pattern in patterns:
        clean = pattern.removeprefix("./")
        if clean.startswith("/"):
            # Absolute paths (e.g., /etc/claude-code/skills/**) are system-level
            # and cannot be relative-globbed under scan_root — skip
            continue
        if "*" not in clean:
            if (scan_root / clean).exists():
                return True
        else:
            try:
                next(scan_root.glob(clean))
                return True
            except StopIteration:
                pass
    return False


# ===========================================================================
# Mechanism 2: Capability gates (for displayed project level)
# ===========================================================================

# Level → capability mapping. Hardcoded — v4 levels.yml no longer has
# capability keys, so we don't load from YAML.
LEVEL_CAPS: dict[str, list[str]] = {
    "L0": [],
    "L1": ["instruction_file"],
    "L2": ["explicit_constraints", "size_controlled"],
    "L3": ["external_references", "multiple_files"],
    "L4": ["path_scoping"],
    "L5": ["org_policy", "navigation"],
    "L6": ["dynamic_context", "extensibility", "state_persistence"],
}

# Capability → detection mapping (CLI-owned).
# Each lambda takes a DetectedFeatures and returns bool.
FEATURE_DETECTORS: dict[str, Callable[..., bool]] = {
    # L1
    "instruction_file": lambda f: f.has_instruction_file,
    # L2
    "explicit_constraints": lambda f: f.has_explicit_constraints,
    "size_controlled": lambda f: f.is_size_controlled,
    # L3
    "external_references": lambda f: f.has_imports or f.has_multiple_instruction_files,
    "multiple_files": lambda f: f.has_multiple_instruction_files,
    # L4
    "path_scoping": lambda f: f.has_path_scoped_rules or f.is_abstracted,
    # L5
    "org_policy": lambda f: f.has_shared_files,
    "navigation": lambda f: f.has_backbone or f.component_count >= 3,
    # L6
    "dynamic_context": lambda f: f.has_skills_dir,
    "extensibility": lambda f: f.has_mcp_config,
    "state_persistence": lambda f: f.has_memory_dir,
}


def determine_level_from_gates(features: DetectedFeatures) -> Level:
    """Determine project level using cumulative capability walk.

    A project is at the highest level where ALL levels L1 through N
    have at least one detected capability (OR within level, AND across levels).

    Walk from L6 down to L1, find highest where all cumulative levels pass.
    """
    for level in reversed(_LEVEL_ORDER):
        if _all_levels_pass(features, level):
            return level

    return Level.L0


def _all_levels_pass(features: DetectedFeatures, target_level: Level) -> bool:
    """Check if all levels from L1 through target_level have at least one capability."""
    target_index = _LEVEL_ORDER.index(target_level)
    return all(_level_has_capability(features, lvl.value) for lvl in _LEVEL_ORDER[: target_index + 1])


def _level_has_capability(features: DetectedFeatures, level_key: str) -> bool:
    """Check if at least one capability at the given level is detected (OR)."""
    capabilities = LEVEL_CAPS.get(level_key, [])
    if not capabilities:
        return True
    return any(_detect_capability(features, cap_id) for cap_id in capabilities)


def _detect_capability(features: DetectedFeatures, capability_id: str) -> bool:
    """Check if a capability is detected for the given features."""
    detector = FEATURE_DETECTORS.get(capability_id)
    if detector is None:
        return False
    return detector(features)


def detect_orphan_features(features: DetectedFeatures, base_level: Level) -> bool:
    """Check if project has capabilities detected above base level.

    Example: L2 project with skills directory (L6 feature) → has_orphan = True
    Display as "L2+" to indicate advanced features present.
    """
    if base_level == Level.L6:
        return False

    base_index = _LEVEL_ORDER.index(base_level) if base_level in _LEVEL_ORDER else -1

    for level in _LEVEL_ORDER[base_index + 1 :]:
        capabilities = LEVEL_CAPS.get(level.value, [])
        for cap_id in capabilities:
            if _detect_capability(features, cap_id):
                return True

    return False
