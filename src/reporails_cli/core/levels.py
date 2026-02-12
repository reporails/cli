"""Level configuration and capability-based level detection.

Capability taxonomy and level definitions loaded from framework registry.
Detection logic (how to detect each capability) is CLI-owned.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from typing import TYPE_CHECKING

import yaml

from reporails_cli.core.bootstrap import get_rules_path
from reporails_cli.core.models import Level

if TYPE_CHECKING:
    from reporails_cli.core.models import DetectedFeatures

# Level labels — canonical mapping (must match framework registry/levels.yml)
LEVEL_LABELS: dict[Level, str] = {
    Level.L0: "Absent",
    Level.L1: "Basic",
    Level.L2: "Scoped",
    Level.L3: "Structured",
    Level.L4: "Abstracted",
    Level.L5: "Maintained",
    Level.L6: "Adaptive",
}

# Ordered levels for walking (L1 → L6)
_LEVEL_ORDER = [Level.L1, Level.L2, Level.L3, Level.L4, Level.L5, Level.L6]

# Capabilities whose detection depends on content analysis (regex Phase 2).
# When skip_content=True, these are treated as detected (optimistic preliminary).
CONTENT_CAPABILITIES: frozenset[str] = frozenset(
    {
        "project_constraints",
        "path_scoping",
    }
)

# Fallback level→capability mapping when framework registry is unavailable.
# Mirrors registry/levels.yml — updated when framework version bumps.
_FALLBACK_LEVEL_CAPS: dict[str, list[str]] = {
    "L0": [],
    "L1": ["instruction_file"],
    "L2": ["project_constraints", "size_controlled"],
    "L3": ["external_references", "multiple_files"],
    "L4": ["path_scoping"],
    "L5": ["structural_integrity", "org_policy", "navigation"],
    "L6": ["dynamic_context", "extensibility", "state_persistence"],
}

# ---------------------------------------------------------------------------
# Capability → detection mapping (CLI-owned)
# ---------------------------------------------------------------------------

CAPABILITY_DETECTORS: dict[str, Callable[[DetectedFeatures], bool]] = {
    # L1
    "instruction_file": lambda f: f.has_instruction_file,
    # L2
    "project_constraints": lambda f: f.has_explicit_constraints,
    "size_controlled": lambda f: f.is_size_controlled,
    # L3
    "external_references": lambda f: f.has_imports,
    "multiple_files": lambda f: f.has_multiple_instruction_files,
    # L4
    "path_scoping": lambda f: f.has_path_scoped_rules or f.is_abstracted,
    # L5
    "structural_integrity": lambda _f: False,  # Not filesystem-detectable
    "org_policy": lambda f: f.has_shared_files,
    "navigation": lambda f: f.has_backbone or f.component_count >= 3,
    # L6
    "dynamic_context": lambda f: f.has_skills_dir,
    "extensibility": lambda f: f.has_mcp_config,
    "state_persistence": lambda f: f.has_memory_dir,
}


# ---------------------------------------------------------------------------
# Framework registry loading
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _load_level_capabilities() -> dict[str, list[str]]:
    """Load level → capability mapping from framework registry.

    Returns dict like: {"L1": ["instruction_file"], "L2": [...], ...}
    Falls back to hardcoded mapping if framework not downloaded yet.

    Returns:
        Level → capability list mapping
    """
    levels_path = get_rules_path() / "registry" / "levels.yml"
    if not levels_path.exists():
        return _FALLBACK_LEVEL_CAPS

    try:
        data = yaml.safe_load(levels_path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return _FALLBACK_LEVEL_CAPS

    result: dict[str, list[str]] = {}
    for level_key, level_data in data.get("levels", {}).items():
        if isinstance(level_data, dict):
            result[level_key] = level_data.get("capabilities", [])
    return result if result else _FALLBACK_LEVEL_CAPS


def get_level_labels() -> dict[Level, str]:
    """Get all level labels."""
    return LEVEL_LABELS


# ---------------------------------------------------------------------------
# Level determination
# ---------------------------------------------------------------------------


def _detect_capability(
    features: DetectedFeatures,
    capability_id: str,
    skip_content: bool = False,
) -> bool:
    """Check if a capability is detected for the given features.

    Args:
        features: Detected project features
        capability_id: Capability identifier from registry
        skip_content: If True, content-dependent capabilities treated as detected

    Returns:
        True if capability is detected
    """
    if skip_content and capability_id in CONTENT_CAPABILITIES:
        return True

    detector = CAPABILITY_DETECTORS.get(capability_id)
    if detector is None:
        return False
    return detector(features)


def _level_has_capability(
    features: DetectedFeatures,
    level_key: str,
    level_caps: dict[str, list[str]],
    skip_content: bool = False,
) -> bool:
    """Check if at least one capability at the given level is detected (OR).

    Args:
        features: Detected project features
        level_key: Level identifier (e.g., "L2")
        level_caps: Level → capability mapping from framework
        skip_content: If True, content capabilities treated as detected

    Returns:
        True if at least one capability at this level is detected
    """
    capabilities = level_caps.get(level_key, [])
    if not capabilities:
        # Level with no capabilities defined — treated as passing
        return True
    return any(_detect_capability(features, cap_id, skip_content) for cap_id in capabilities)


def determine_level_from_gates(
    features: DetectedFeatures,
    skip_content: bool = False,
) -> Level:
    """Determine capability level using cumulative capability ladder.

    A project is at the highest level where ALL levels L1 through N
    have at least one detected capability (OR within level, AND across levels).

    Args:
        features: Detected project features
        skip_content: If True, content capabilities treated as detected (preliminary)

    Returns:
        Highest level where all cumulative capabilities pass
    """
    level_caps = _load_level_capabilities()

    # Walk from L6 down to L1, find highest where all cumulative levels pass
    for level in reversed(_LEVEL_ORDER):
        if _all_levels_pass(features, level, level_caps, skip_content):
            return level

    return Level.L0


def _all_levels_pass(
    features: DetectedFeatures,
    target_level: Level,
    level_caps: dict[str, list[str]],
    skip_content: bool,
) -> bool:
    """Check if all levels from L1 through target_level have at least one capability.

    Args:
        features: Detected project features
        target_level: Level to check up to
        level_caps: Level → capability mapping
        skip_content: If True, content capabilities treated as detected

    Returns:
        True if all cumulative levels pass
    """
    target_index = _LEVEL_ORDER.index(target_level)

    for lvl in _LEVEL_ORDER[: target_index + 1]:
        if not _level_has_capability(features, lvl.value, level_caps, skip_content):
            return False

    return True


def detect_orphan_features(features: DetectedFeatures, base_level: Level) -> bool:
    """Check if project has capabilities detected above base level.

    Example: L3 project with skills directory (L6 feature) → has_orphan = True
    Display as "L3+" to indicate advanced features present.

    Args:
        features: Detected project features
        base_level: Base capability level

    Returns:
        True if capabilities above base level are detected
    """
    level_caps = _load_level_capabilities()

    base_index = _LEVEL_ORDER.index(base_level)

    # Check capabilities from levels above base
    for level in _LEVEL_ORDER[base_index + 1 :]:
        capabilities = level_caps.get(level.value, [])
        for cap_id in capabilities:
            if _detect_capability(features, cap_id):
                return True

    return False
