"""Level configuration and project level determination.

Two level mechanisms coexist:

1. Target existence (determine_project_level): computes present file types
   for rule applicability. Uses axis divergence from file type properties.

2. Capability gates (determine_level_from_gates): computes the displayed
   project level from detected features. The level is the highest level
   whose own capability is present — a project may skip a level (e.g.
   skills + sub-agents + memory with no path-scoped rules) and still reach
   the level its highest surface supports.

The displayed level comes from (2). Rule applicability comes from (1).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.platform.dto.models import Level

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.models import ClassifiedFile, FileTypeDeclaration
    from reporails_cli.core.platform.dto.results import DetectedFeatures

# Level labels — canonical mapping per `docs/capability-levels.md` ladder.
LEVEL_LABELS: dict[Level, str] = {
    Level.L0: "System",
    Level.L1: "Primer",
    Level.L2: "Composite",
    Level.L3: "Scoped",
    Level.L4: "Delegated",
    Level.L5: "Abstracted",
    Level.L6: "Governed",
    Level.L7: "Adaptive",
}

# Ordered levels for walking (L1 → L7)
_LEVEL_ORDER = [Level.L1, Level.L2, Level.L3, Level.L4, Level.L5, Level.L6, Level.L7]


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

# Level → capability mapping per `docs/capability-levels.md` detection table.
# L1=Primer, L2=Composite, L3=Scoped, L4=Delegated, L5=Abstracted,
# L6=Governed, L7=Adaptive. Each level adds one architectural capability;
# the displayed level is the highest level whose own capability is present,
# per the ladder's "highest architectural capability present" rule — a
# project may skip a level (skills + sub-agents + memory with no path-scoped
# rules) and still reach the level its highest surface supports.
LEVEL_CAPS: dict[str, list[str]] = {
    "L0": [],
    "L1": ["instruction_file"],
    "L2": ["multiple_files"],
    "L3": ["path_scoping"],
    "L4": ["skills"],
    "L5": ["agents"],
    "L6": ["governance"],
    "L7": ["adaptive_memory"],
}

# Capability → detection mapping (CLI-owned).
# Each lambda takes a DetectedFeatures and returns bool.
FEATURE_DETECTORS: dict[str, Callable[..., bool]] = {
    # L1 — Primer: one main file present
    "instruction_file": lambda f: f.has_instruction_file,
    # L2 — Composite: multiple main files in the project (user-scope files do not count)
    "multiple_files": lambda f: f.has_multiple_instruction_files,
    # L3 — Scoped: path-conditional rule loading
    "path_scoping": lambda f: f.has_path_scoped_rules,
    # L4 — Delegated: skills directory with definitions
    "skills": lambda f: f.has_skills_dir,
    # L5 — Abstracted: sub-agent definitions
    "agents": lambda f: f.has_subagents,
    # L6 — Governed: hooks (enforcement outside the model's context)
    "governance": lambda f: bool(f.hook_files),
    # L7 — Adaptive: auto-memory or self-modifying instruction sources
    "adaptive_memory": lambda f: f.has_auto_memory or f.has_memory_dir,
}


def determine_level_from_gates(features: DetectedFeatures) -> Level:
    """Determine project level: the highest level whose own capability is present.

    Per the capability-model ladder, each level adds one architectural
    capability and a project may skip levels — skills (L4), sub-agents (L5),
    governance (L6) and adaptive memory (L7) with no path-scoped rules (L3) is
    a real and common shape. The displayed level is the highest level with a
    detected capability, not the highest contiguous run, so such a project
    reaches the level its richest surface supports instead of being capped at
    L2. A project with no instruction file at all is L0.
    """
    if not _level_has_capability(features, Level.L1.value):
        return Level.L0

    highest = Level.L0
    for level in _LEVEL_ORDER:
        if _level_has_capability(features, level.value):
            highest = level
    return highest


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
