"""Data models for reporails. All models are frozen (immutable) where possible."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Category(str, Enum):
    """Rule categories matching framework."""

    STRUCTURE = "structure"
    CONTENT = "content"
    MAINTENANCE = "maintenance"
    GOVERNANCE = "governance"
    EFFICIENCY = "efficiency"


# Category code -> Category enum mapping (first letter of rule ID)
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
    DETERMINISTIC = "deterministic"  # Regex pattern -> direct violation
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
    deterministic (regex pattern), or semantic (LLM evaluation).
    """

    id: str  # e.g., "CORE:S:0001:check:0001"
    severity: Severity
    type: str = "deterministic"  # "mechanical" | "deterministic" | "semantic"
    name: str = ""  # Human-readable (optional)
    check: str | None = None  # Mechanical function name
    args: dict[str, Any] | None = None  # Mechanical check arguments
    negate: bool = False  # If True, finding = pass (content present), no finding = violation


@dataclass(frozen=True)
class Rule:  # pylint: disable=too-many-instance-attributes
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

    rule_id: str  # e.g., "CORE:S:0005"
    rule_title: str  # e.g., "Instruction File Size Limit"
    location: str  # e.g., "CLAUDE.md:45"
    message: str  # From rule definition
    severity: Severity
    check_id: str | None = None  # e.g., "CORE:S:0005:check:0001"


@dataclass(frozen=True)
class JudgmentRequest:  # pylint: disable=too-many-instance-attributes
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


# Re-exports for backward compatibility
from reporails_cli.core.results import (  # noqa: E402
    AgentConfig,
    CapabilityResult,
    CategoryStats,
    ContentFeatures,
    DetectedFeatures,
    FrictionEstimate,
    GlobalConfig,
    InitResult,
    PendingSemantic,
    ProjectConfig,
    ScanDelta,
    SkippedExperimental,
    UpdateResult,
    ValidationResult,
)

__all__ = [
    "CATEGORY_CODES",
    "AgentConfig",
    "CapabilityResult",
    "Category",
    "CategoryStats",
    "Check",
    "ContentFeatures",
    "DetectedFeatures",
    "FrictionEstimate",
    "GlobalConfig",
    "InitResult",
    "JudgmentRequest",
    "JudgmentResponse",
    "Level",
    "PatternConfidence",
    "PendingSemantic",
    "ProjectConfig",
    "Rule",
    "RuleType",
    "ScanDelta",
    "Severity",
    "SkippedExperimental",
    "Tier",
    "UpdateResult",
    "ValidationResult",
    "Violation",
]
