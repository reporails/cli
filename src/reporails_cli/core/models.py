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
    """How the rule is detected."""

    DETERMINISTIC = "deterministic"  # Exact match, counts, file exists
    HEURISTIC = "heuristic"  # Pattern matching, tunable
    SEMANTIC = "semantic"  # Requires LLM judgment


class Severity(str, Enum):
    """Violation severity levels."""

    CRITICAL = "critical"  # -25 points
    HIGH = "high"  # -15 points
    MEDIUM = "medium"  # -10 points
    LOW = "low"  # -5 points


class Level(str, Enum):
    """Capability levels from framework."""

    L1 = "L1"  # Absent
    L2 = "L2"  # Minimal
    L3 = "L3"  # Basic
    L4 = "L4"  # Standard
    L5 = "L5"  # Advanced
    L6 = "L6"  # Governed


@dataclass(frozen=True)
class Antipattern:
    """An antipattern that a rule detects."""

    id: str  # e.g., "A3"
    name: str  # e.g., "Root file > 200 lines"
    severity: Severity
    points: int  # Negative, e.g., -25


@dataclass
class Rule:
    """A rule definition loaded from frontmatter."""

    id: str  # e.g., "S1"
    title: str  # e.g., "Size Limits"
    category: Category
    type: RuleType
    level: str  # e.g., "L2+" or "L4"
    scoring: int  # Points when rule passes

    # Optional
    detection: str | None = None
    sources: list[int] = field(default_factory=list)
    see_also: list[str] = field(default_factory=list)
    antipatterns: list[Antipattern] = field(default_factory=list)
    validation: str | None = None

    # Heuristic/semantic fields (for LLM confirmation)
    question: str | None = None
    criteria: str | None = None

    # Paths (set after loading)
    md_path: Path | None = None
    yml_path: Path | None = None


@dataclass(frozen=True)
class Violation:
    """A rule violation found during analysis."""

    rule_id: str
    rule_title: str
    location: str  # e.g., "CLAUDE.md:45"
    message: str
    severity: Severity
    points: int  # Negative


@dataclass(frozen=True)
class JudgmentRequest:
    """Request for host LLM to evaluate semantic rule."""

    rule_id: str
    rule_title: str
    content: str  # The actual text from CLAUDE.md
    location: str  # e.g., "CLAUDE.md:45"
    question: str
    criteria: dict[str, str]
    examples: dict[str, list[str]]
    choices: list[str]
    pass_value: str
    severity: Severity
    points_if_fail: int


@dataclass(frozen=True)
class JudgmentResponse:
    """Response from host LLM after evaluating semantic rule."""

    rule_id: str
    verdict: str  # One of the choices
    reason: str
    passed: bool  # Computed: verdict == pass_value


@dataclass(frozen=True)
class ValidationResult:
    """Complete validation output."""

    score: float  # 0.0-10.0 scale
    level: Level  # Capability level (determined by features)
    violations: tuple[Violation, ...]  # Immutable
    judgment_requests: tuple[JudgmentRequest, ...]
    rules_checked: int  # Total rules checked (applicable to this setup)
    rules_passed: int
    rules_failed: int
    time_waste_estimate: dict[str, int]  # Minutes by category
    feature_summary: str  # Human-readable summary of detected features
    violation_points: int  # Total deduction points from violations


@dataclass(frozen=True)
class UpdateResult:
    """Result of rules update operation."""

    success: bool
    message: str
    rules_path: Path | None = None
    rules_count: int = 0
