"""Level configuration and project level determination.

Capability gates (determine_level_from_gates) compute the displayed project
level from detected features. The level is the highest level whose own
capability is present — a project may skip a level (e.g. skills + sub-agents
+ memory with no path-scoped rules) and still reach the level its highest
surface supports.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from reporails_cli.core.platform.dto.models import Level

if TYPE_CHECKING:
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
FEATURE_DETECTORS: dict[str, Callable[[DetectedFeatures], bool]] = {
    # L1 — Primer: one main file present
    "instruction_file": lambda f: f.has_instruction_file,
    # L2 — Composite: multiple main files in the project (user-scope files do not count)
    "multiple_files": lambda f: f.discovery.has_multiple_instruction_files,
    # L3 — Scoped: path-conditional rule loading
    "path_scoping": lambda f: f.has_path_scoped_rules,
    # L4 — Delegated: skills directory with definitions
    "skills": lambda f: f.has_skills_dir,
    # L5 — Abstracted: sub-agent definitions
    "agents": lambda f: f.has_subagents,
    # L6 — Governed: hooks (enforcement outside the model's context)
    "governance": lambda f: bool(f.hook_files),
    # L7 — Adaptive: auto-memory or self-modifying instruction sources
    "adaptive_memory": lambda f: f.memory.has_auto_memory or f.memory.has_memory_dir,
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
