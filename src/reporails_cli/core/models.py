"""Data models for reporails. All models are frozen (immutable) where possible."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reporails_cli.core.cache import AnalyticsEntry


class Category(str, Enum):
    """Rule categories matching framework."""

    STRUCTURE = "structure"
    CONTENT = "content"
    MAINTENANCE = "maintenance"
    GOVERNANCE = "governance"
    EFFICIENCY = "efficiency"


# Category code → Category enum mapping (first letter of rule ID)
CATEGORY_CODES: dict[str, Category] = {
    "S": Category.STRUCTURE,
    "C": Category.CONTENT,
    "E": Category.EFFICIENCY,
    "M": Category.MAINTENANCE,
    "G": Category.GOVERNANCE,
}


class RuleType(str, Enum):
    """How the rule is detected. Three types."""

    MECHANICAL = "mechanical"  # Python structural check
    DETERMINISTIC = "deterministic"  # OpenGrep pattern → direct violation
    SEMANTIC = "semantic"  # LLM judgment required


class Severity(str, Enum):
    """Violation severity levels."""

    CRITICAL = "critical"  # Weight: 5.5
    HIGH = "high"  # Weight: 4.0
    MEDIUM = "medium"  # Weight: 2.5
    LOW = "low"  # Weight: 1.0


class Tier(str, Enum):
    """Rule confidence tier, derived from backing source weights."""

    CORE = "core"
    EXPERIMENTAL = "experimental"


class PatternConfidence(str, Enum):
    """How reliable a rule's detection pattern is."""

    VERY_HIGH = "very_high"  # Exact structural match
    HIGH = "high"  # Tight regex, rare false positives
    MEDIUM = "medium"  # Reasonable regex, some edge cases
    LOW = "low"  # Broad match, known false positives
    VERY_LOW = "very_low"  # Placeholder or minimal pattern


class Level(str, Enum):
    """Capability levels from framework."""

    L0 = "L0"  # Absent
    L1 = "L1"  # Basic
    L2 = "L2"  # Scoped
    L3 = "L3"  # Structured
    L4 = "L4"  # Abstracted
    L5 = "L5"  # Maintained
    L6 = "L6"  # Adaptive


@dataclass(frozen=True)
class Check:
    """A specific check within a rule.

    Checks have a type matching their gate: mechanical (Python function),
    deterministic (OpenGrep pattern), or semantic (LLM evaluation).
    """

    id: str  # e.g., "CORE:S:0001:check:0001"
    severity: Severity
    type: str = "deterministic"  # "mechanical" | "deterministic" | "semantic"
    name: str = ""  # Human-readable (optional)
    check: str | None = None  # Mechanical function name
    args: dict[str, Any] | None = None  # Mechanical check arguments
    negate: bool = False  # If True, finding = pass (content present), no finding = violation


@dataclass
class Rule:
    """A rule definition loaded from framework frontmatter."""

    # Required (from frontmatter)
    id: str  # e.g., "CORE:S:0001"
    title: str  # e.g., "Instruction File Exists"
    category: Category
    type: RuleType
    level: str  # e.g., "L2" - minimum level this rule applies to

    # Identity
    slug: str = ""  # e.g., "instruction-file-exists"
    targets: str = ""  # e.g., "{{instruction_files}}"
    supersedes: str | None = None  # Coordinate of rule this replaces

    # Checks (all rule types)
    checks: list[Check] = field(default_factory=list)

    # Semantic fields (semantic rules)
    question: str | None = None
    criteria: list[dict[str, str]] | str | None = None  # [{key, check}, ...] or string
    choices: list[dict[str, str]] | list[str] | None = None  # [{value, label}, ...]
    pass_value: str | None = None
    examples: dict[str, list[str]] | None = None  # {good: [...], bad: [...]}

    # References
    sources: list[str] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)
    backed_by: list[str] = field(default_factory=list)  # Source IDs from sources.yml

    # Pattern quality
    pattern_confidence: PatternConfidence | None = None

    # Paths (set after loading)
    md_path: Path | None = None
    yml_path: Path | None = None


@dataclass(frozen=True)
class Violation:
    """A rule violation found during analysis."""

    rule_id: str  # e.g., "S1"
    rule_title: str  # e.g., "Size Limits"
    location: str  # e.g., "CLAUDE.md:45"
    message: str  # From OpenGrep
    severity: Severity
    check_id: str | None = None  # e.g., "S1-root-too-long"


@dataclass(frozen=True)
class JudgmentRequest:
    """Request for host LLM to evaluate semantic rule."""

    rule_id: str
    rule_title: str
    content: str  # Text to evaluate
    location: str  # e.g., "CLAUDE.md"
    question: str  # What to evaluate
    criteria: dict[str, str]  # {key: check, ...}
    examples: dict[str, list[str]]  # {good: [...], bad: [...]}
    choices: list[str]  # [value, ...]
    pass_value: str  # Which choice means "pass"
    severity: Severity
    points_if_fail: int


@dataclass(frozen=True)
class JudgmentResponse:
    """Response from host LLM after evaluation."""

    rule_id: str
    verdict: str  # One of the choice values
    reason: str  # Explanation
    passed: bool  # verdict == pass_value


# =============================================================================
# Feature Detection Models
# =============================================================================


@dataclass
class DetectedFeatures:
    """Features detected in a project for capability scoring.

    Populated in two phases:
    - Phase 1: Filesystem detection (applicability.py)
    - Phase 2: Content detection (capability.py via OpenGrep)
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

    # Symlink resolution (for OpenGrep extra targets)
    resolved_symlinks: list[Path] = field(default_factory=list)

    # L2 capabilities
    is_size_controlled: bool = False  # Root instruction file under size threshold

    # L6 capabilities
    has_skills_dir: bool = False  # .claude/skills/ etc. with content
    has_mcp_config: bool = False  # .mcp.json or similar
    has_memory_dir: bool = False  # Memory/state persistence

    # === Phase 2: Content detection (OpenGrep) ===

    # Content analysis
    has_sections: bool = False  # Has H2+ headers
    has_imports: bool = False  # @imports or file references
    has_explicit_constraints: bool = False  # MUST/NEVER keywords
    has_path_scoped_rules: bool = False  # Rules with paths: frontmatter


@dataclass(frozen=True)
class ContentFeatures:
    """Intermediate result from OpenGrep content analysis."""

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
    auto_update_check: bool = True


@dataclass
class ProjectConfig:
    """Project-level configuration (.reporails/config.yml)."""

    framework_version: str | None = None  # Pin version
    packages: list[str] = field(default_factory=list)  # Project rule packages
    disabled_rules: list[str] = field(default_factory=list)
    overrides: dict[str, dict[str, str]] = field(default_factory=dict)
    experimental: bool | list[str] = False  # True, False, or list of rule IDs
    recommended: bool = True  # Include recommended rules (opt out with false)
    exclude_dirs: list[str] = field(default_factory=list)  # Directory names to exclude


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
        curr_num = int(current_level[1]) if current_level.startswith("L") else 0
        prev_num = int(previous.level[1]) if previous.level.startswith("L") else 0
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
    rules: tuple[str, ...]  # Rule IDs (e.g., "E2", "S3")


@dataclass(frozen=True)
class ValidationResult:
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
    opengrep_path: Path | None
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
