"""Data models for reporails. All models are frozen (immutable) where possible."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Category(str, Enum):
    """Rule categories matching framework."""

    STRUCTURE = "structure"
    CONTENT = "content"
    MAINTENANCE = "maintenance"
    GOVERNANCE = "governance"
    EFFICIENCY = "efficiency"


class RuleType(str, Enum):
    """How the rule is detected. Two types only."""

    DETERMINISTIC = "deterministic"  # OpenGrep pattern → direct violation
    SEMANTIC = "semantic"  # LLM judgment required


class Severity(str, Enum):
    """Violation severity levels."""

    CRITICAL = "critical"  # Weight: 5.5
    HIGH = "high"  # Weight: 4.0
    MEDIUM = "medium"  # Weight: 2.5
    LOW = "low"  # Weight: 1.0


class Level(str, Enum):
    """Capability levels from framework."""

    L1 = "L1"  # Absent
    L2 = "L2"  # Basic
    L3 = "L3"  # Structured
    L4 = "L4"  # Abstracted
    L5 = "L5"  # Governed
    L6 = "L6"  # Adaptive


@dataclass(frozen=True)
class Check:
    """A specific check within a rule. Maps to OpenGrep pattern."""

    id: str  # e.g., "S1-root-too-long"
    name: str  # e.g., "Root file exceeds 200 lines"
    severity: Severity


@dataclass
class Rule:
    """A rule definition loaded from framework frontmatter."""

    # Required (from frontmatter)
    id: str  # e.g., "S1"
    title: str  # e.g., "Size Limits"
    category: Category
    type: RuleType
    level: str  # e.g., "L2" - minimum level this rule applies to

    # Checks (deterministic rules)
    checks: list[Check] = field(default_factory=list)

    # Semantic fields (semantic rules)
    question: str | None = None
    criteria: list[dict[str, str]] | str | None = None  # [{key, check}, ...] or string
    choices: list[dict[str, str]] | list[str] | None = None  # [{value, label}, ...]
    pass_value: str | None = None
    examples: dict[str, list[str]] | None = None  # {good: [...], bad: [...]}

    # References
    sources: list[int] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)

    # Legacy field names (for backward compatibility during transition)
    detection: str | None = None
    scoring: int = 0
    validation: str | None = None

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
    has_rules_dir: bool = False  # .claude/rules/, .cursor/rules/, etc.
    has_shared_files: bool = False  # .shared/, shared/, cross-refs
    has_backbone: bool = False  # .reporails/backbone.yml

    # Discovery
    component_count: int = 0  # Components from discovery
    instruction_file_count: int = 0
    has_multiple_instruction_files: bool = False
    has_hierarchical_structure: bool = False  # nested CLAUDE.md files
    detected_agents: list[str] = field(default_factory=list)

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
    capability_score: int  # 0-12
    level: Level  # Base level (L1-L6)
    has_orphan_features: bool  # Has features above base level (display as L3+)
    feature_summary: str  # Human-readable


@dataclass(frozen=True)
class FrictionEstimate:
    """Time waste estimate from violations."""

    level: str  # "high", "medium", "low", "none"
    total_minutes: int
    by_category: dict[str, int]  # {"S": 5, "C": 3, ...}


# =============================================================================
# Configuration Models
# =============================================================================


@dataclass
class GlobalConfig:
    """Global user configuration (~/.reporails/config.yml)."""

    framework_path: Path | None = None  # Local override (dev)
    auto_update_check: bool = True


@dataclass
class ProjectConfig:
    """Project-level configuration (.reporails/config.yml)."""

    framework_version: str | None = None  # Pin version
    disabled_rules: list[str] = field(default_factory=list)
    overrides: dict[str, dict[str, str]] = field(default_factory=dict)


# =============================================================================
# Result Models
# =============================================================================


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
    # Legacy fields for backward compat
    time_waste_estimate: dict[str, int] = field(default_factory=dict)
    violation_points: int = 0


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
