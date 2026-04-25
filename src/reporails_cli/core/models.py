"""Data models for reporails.

Schema-mapped types (Check, Rule, FileMatch, FileTypeDeclaration, ClassifiedFile)
use Pydantic BaseModel — frozen, validated, and self-documenting. The model IS
the schema: use Rule.model_json_schema() to export.

Internal types (LocalFinding, Violation, JudgmentRequest, JudgmentResponse)
remain plain dataclasses — no schema contract needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Category(str, Enum):
    """Rule categories matching framework."""

    STRUCTURE = "structure"
    COHERENCE = "coherence"
    DIRECTION = "direction"
    EFFICIENCY = "efficiency"
    MAINTENANCE = "maintenance"
    GOVERNANCE = "governance"


# Category code -> Category enum mapping (first letter of rule ID)
CATEGORY_CODES: dict[str, Category] = {
    "S": Category.STRUCTURE,
    "C": Category.COHERENCE,
    "D": Category.DIRECTION,
    "E": Category.EFFICIENCY,
    "M": Category.MAINTENANCE,
    "G": Category.GOVERNANCE,
}


class RuleType(str, Enum):
    """How the rule is checked locally."""

    MECHANICAL = "mechanical"  # Python structural check
    DETERMINISTIC = "deterministic"  # Regex pattern -> direct violation


class Execution(str, Enum):
    """Where the rule's checks execute."""

    LOCAL = "local"  # checks.yml on client
    SERVER = "server"  # diagnostic from API, no local checks


class Severity(str, Enum):
    """Violation severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


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
    """Project levels from framework."""

    L0 = "L0"  # Absent
    L1 = "L1"  # Present
    L2 = "L2"  # Structured
    L3 = "L3"  # Substantive
    L4 = "L4"  # Actionable
    L5 = "L5"  # Refined
    L6 = "L6"  # Adaptive


# ---------------------------------------------------------------------------
# Schema-mapped models (Pydantic) — frozen, validated
# ---------------------------------------------------------------------------


class FileTypeDeclaration(BaseModel):
    """A typed file declaration from agent config file_types section."""

    model_config = ConfigDict(frozen=True)

    name: str  # "main", "scoped_rule", "skill", etc.
    patterns: tuple[str, ...]  # glob patterns
    required: bool = False
    properties: dict[str, str | list[str]] = Field(default_factory=dict)


class ClassifiedFile(BaseModel):
    """A file matched to a type declaration with resolved properties."""

    model_config = ConfigDict(frozen=True)

    path: Path
    file_type: str  # type name from FileTypeDeclaration.name
    properties: dict[str, str | list[str]] = Field(default_factory=dict)


class FileMatch(BaseModel):
    """Property-based file targeting. None properties are wildcards.

    Each property can be:
    - None: wildcard (matches any value)
    - str: exact match
    - list[str]: OR match (value must be in the list)
    """

    model_config = ConfigDict(frozen=True)

    type: list[str] | str | None = None
    scope: list[str] | str | None = None
    format: list[str] | str | None = None
    content_format: list[str] | None = None
    cardinality: list[str] | str | None = None
    lifecycle: list[str] | str | None = None
    maintainer: list[str] | str | None = None
    vcs: list[str] | str | None = None
    loading: list[str] | str | None = None
    precedence: list[str] | str | None = None


class Check(BaseModel):
    """A specific check within a rule.

    Checks have a type matching their gate: mechanical (Python function),
    deterministic (regex pattern), or content_query (atom-based).
    """

    model_config = ConfigDict(frozen=True)

    id: str  # e.g., "CORE.S.0001.file-exists"
    type: str = "deterministic"  # "mechanical" | "deterministic" | "content_query"
    check: str | None = None  # Mechanical function name
    args: dict[str, Any] | None = None  # Mechanical/content_query arguments
    query: str | None = None  # Content query function name (type=content_query)
    expect: str = "present"  # "present" = no match is violation; "absent" = match is violation
    metadata_keys: list[str] = Field(default_factory=list)  # D→M metadata bus keys
    replaces: str = ""  # Check ID from superseded rule to replace (inheritance)
    severity: str = ""  # Check-level severity override (empty = use rule severity)
    message: str = ""  # Check-level message (empty = use check result message)


class Rule(BaseModel):
    """A rule definition loaded from framework frontmatter.

    The single source of truth for rule structure. Use Rule.model_json_schema()
    to export the schema for external consumers.
    """

    model_config = ConfigDict(frozen=True)

    # Required (from frontmatter)
    id: str  # e.g., "CORE:S:0001"
    title: str  # e.g., "Instruction File Exists"
    category: Category
    type: RuleType
    severity: Severity = Severity.MEDIUM  # Rule-level severity

    # Identity
    slug: str = ""  # e.g., "instruction-file-exists"
    execution: Execution = Execution.LOCAL  # Where checks run
    match: FileMatch | None = None  # Property-based file targeting
    supersedes: str | None = None  # Coordinate of rule this replaces
    inherited: str | None = None  # Coordinate of parent rule to inherit checks from (both stay active)
    depends_on: list[str] = Field(default_factory=list)  # Rule coordinates that must pass first

    # Checks (all rule types)
    checks: list[Check] = Field(default_factory=list)

    # References
    sources: list[str] = Field(default_factory=list)
    see_also: list[str] = Field(default_factory=list)
    backed_by: list[str] = Field(default_factory=list)  # Source IDs from sources.yml

    # Pattern quality
    pattern_confidence: PatternConfidence | None = None

    # Paths (set after loading)
    md_path: Path | None = None
    yml_path: Path | None = None


# ---------------------------------------------------------------------------
# Internal types (dataclasses) — no schema contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LocalFinding:
    """A finding from local M-probe or D-level client check."""

    file: str  # relative file path
    line: int  # 1-based line number
    severity: str  # "error" | "warning" | "info"
    rule: str  # rule_id (M probes) or theory label (client checks)
    message: str  # human-readable description
    fix: str = ""  # suggested fix text
    source: str = "local"  # "m_probe" | "client_check"
    check_id: str = ""  # specific check that triggered this


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


# Re-exports for backward compatibility
from reporails_cli.core.results import (  # noqa: E402
    AgentConfig,
    CategoryStats,
    DetectedFeatures,
    FrictionEstimate,
    GlobalConfig,
    InitResult,
    PendingSemantic,
    ProjectConfig,
    RuleResult,
    ScanDelta,
    UpdateResult,
    ValidationResult,
)

__all__ = [
    "CATEGORY_CODES",
    "AgentConfig",
    "Category",
    "CategoryStats",
    "Check",
    "ClassifiedFile",
    "DetectedFeatures",
    "FileMatch",
    "FileTypeDeclaration",
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
    "RuleResult",
    "RuleType",
    "ScanDelta",
    "Severity",
    "Tier",
    "UpdateResult",
    "ValidationResult",
    "Violation",
]
