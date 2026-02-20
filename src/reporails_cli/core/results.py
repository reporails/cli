"""Result and configuration models split from models.py."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reporails_cli.core.models import Level, Violation

if TYPE_CHECKING:
    from reporails_cli.core.cache import AnalyticsEntry

from reporails_cli.core.models import JudgmentRequest

# =============================================================================
# Feature Detection Models
# =============================================================================


@dataclass
class DetectedFeatures:  # pylint: disable=too-many-instance-attributes
    """Features detected in a project for capability scoring.

    Populated in two phases:
    - Phase 1: Filesystem detection (applicability.py)
    - Phase 2: Content detection (capability.py via regex)
    """

    # === Phase 1: Filesystem detection ===

    # Base existence
    has_instruction_file: bool = False  # Any instruction file found
    has_claude_md: bool = False  # CLAUDE.md at root (legacy compat)

    # Directory structure
    is_abstracted: bool = False  # .claude/rules/, .claude/skills/, etc.
    has_shared_files: bool = False  # .shared/, shared/, cross-refs
    has_backbone: bool = False  # .reporails/backbone.yml

    # Discovery
    component_count: int = 0  # Components from discovery
    instruction_file_count: int = 0
    has_multiple_instruction_files: bool = False
    has_hierarchical_structure: bool = False  # nested CLAUDE.md files
    detected_agents: list[str] = field(default_factory=list)

    # Symlink resolution (for regex engine extra targets)
    resolved_symlinks: list[Path] = field(default_factory=list)

    # L2 capabilities
    is_size_controlled: bool = False  # Root instruction file under size threshold

    # L6 capabilities
    has_skills_dir: bool = False  # .claude/skills/ etc. with content
    has_mcp_config: bool = False  # .mcp.json or similar
    has_memory_dir: bool = False  # Memory/state persistence

    # === Phase 2: Content detection (regex) ===

    # Content analysis
    has_sections: bool = False  # Has H2+ headers
    has_imports: bool = False  # @imports or file references
    has_explicit_constraints: bool = False  # MUST/NEVER keywords
    has_path_scoped_rules: bool = False  # Rules with paths: frontmatter


@dataclass(frozen=True)
class ContentFeatures:
    """Intermediate result from regex content analysis."""

    has_sections: bool = False
    has_imports: bool = False
    has_explicit_constraints: bool = False
    has_path_scoped_rules: bool = False


@dataclass(frozen=True)
class CapabilityResult:
    """Result of capability detection pipeline."""

    features: DetectedFeatures
    level: Level  # Base level (L1-L6)
    has_orphan_features: bool  # Has features above base level (display as L3+)
    feature_summary: str  # Human-readable


@dataclass(frozen=True)
class FrictionEstimate:
    """Friction estimate from violations."""

    level: str  # "extreme", "high", "medium", "small", "none"


@dataclass(frozen=True)
class CategoryStats:
    """Per-category rule statistics for the category summary table."""

    code: str  # "S", "C", "E", "M", "G"
    name: str  # "Structure", "Content", etc.
    total: int
    passed: int
    failed: int
    worst_severity: str | None  # "critical"/"high"/"medium"/"low" or None


# =============================================================================
# Configuration Models
# =============================================================================


@dataclass
class AgentConfig:
    """Agent configuration from framework (agents/{agent}/config.yml)."""

    agent: str = ""
    excludes: list[str] = field(default_factory=list)
    overrides: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class GlobalConfig:
    """Global user configuration (~/.reporails/config.yml)."""

    framework_path: Path | None = None  # Local override (dev)
    recommended_path: Path | None = None  # Local override (dev)
    auto_update_check: bool = True
    default_agent: str = ""
    recommended: bool = True


@dataclass
class ProjectConfig:  # pylint: disable=too-many-instance-attributes
    """Project-level configuration (.reporails/config.yml)."""

    framework_version: str | None = None  # Pin version
    packages: list[str] = field(default_factory=list)  # Project rule packages
    disabled_rules: list[str] = field(default_factory=list)
    overrides: dict[str, dict[str, str]] = field(default_factory=dict)
    experimental: bool | list[str] = False  # True, False, or list of rule IDs
    recommended: bool = True  # Include recommended rules (opt out with false)
    exclude_dirs: list[str] = field(default_factory=list)  # Directory names to exclude
    default_agent: str = ""  # Default agent when --agent not specified (e.g., "claude")


# =============================================================================
# Result Models
# =============================================================================


@dataclass(frozen=True)
class ScanDelta:
    """Comparison between current and previous scan."""

    score_delta: float | None  # None if no previous or unchanged
    level_previous: str | None  # None if unchanged or no previous
    level_improved: bool | None  # True=up, False=down, None=unchanged/no previous
    violations_delta: int | None  # Negative=improvement, positive=regression, None if unchanged

    @classmethod
    def compute(
        cls,
        current_score: float,
        current_level: str,
        current_violations: int,
        previous: AnalyticsEntry | None,
    ) -> ScanDelta:
        """Compute delta from current values and previous scan entry.

        Args:
            current_score: Current scan score
            current_level: Current level (e.g., "L3")
            current_violations: Current violation count
            previous: Previous AnalyticsEntry or None

        Returns:
            ScanDelta with computed differences
        """
        if previous is None:
            return cls(None, None, None, None)

        # Score delta (round to 1 decimal, None if unchanged)
        raw_score_delta = round(current_score - previous.score, 1)
        score_delta = raw_score_delta if raw_score_delta != 0 else None

        # Level comparison (extract number from "L3" etc)
        curr_num = int(current_level[1:]) if current_level.startswith("L") and current_level[1:].isdigit() else 0
        prev_num = int(previous.level[1:]) if previous.level.startswith("L") and previous.level[1:].isdigit() else 0
        if curr_num != prev_num:
            level_previous = previous.level
            level_improved = curr_num > prev_num
        else:
            level_previous = None
            level_improved = None

        # Violations delta (None if unchanged)
        viol_delta = current_violations - previous.violations_count
        violations_delta = viol_delta if viol_delta != 0 else None

        return cls(score_delta, level_previous, level_improved, violations_delta)


@dataclass(frozen=True)
class PendingSemantic:
    """Summary of pending semantic rules for partial evaluation."""

    rule_count: int  # Number of semantic rules pending
    file_count: int  # Files with pending semantic checks
    rules: tuple[str, ...]  # Rule IDs (e.g., "C6", "C10")


@dataclass(frozen=True)
class SkippedExperimental:
    """Summary of skipped experimental rules."""

    rule_count: int  # Number of experimental rules skipped
    rules: tuple[str, ...]  # Rule IDs (e.g., "CORE:C:0004")


@dataclass(frozen=True)
class ValidationResult:  # pylint: disable=too-many-instance-attributes
    """Complete validation output."""

    score: float  # 0.0-10.0 scale
    level: Level  # Capability level
    violations: tuple[Violation, ...]  # Immutable
    judgment_requests: tuple[JudgmentRequest, ...]
    rules_checked: int  # Deterministic rules checked
    rules_passed: int
    rules_failed: int
    feature_summary: str  # Human-readable
    friction: FrictionEstimate
    # Per-category breakdown
    has_orphan_features: bool = False  # Features above base level (display as L3+)
    category_summary: tuple[CategoryStats, ...] = ()
    # Evaluation completeness
    is_partial: bool = True  # True for CLI (pattern-only), False for MCP (includes semantic)
    pending_semantic: PendingSemantic | None = None  # Summary of pending semantic rules
    skipped_experimental: SkippedExperimental | None = None  # Summary of skipped experimental rules


@dataclass(frozen=True)
class InitResult:
    """Result of initialization."""

    success: bool
    rules_path: Path | None
    framework_version: str | None
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class UpdateResult:
    """Result of framework update."""

    success: bool
    message: str
    old_version: str | None = None
    new_version: str | None = None
    rules_path: Path | None = None
    rules_count: int = 0
