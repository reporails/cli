"""Data models for reporails.

Schema-mapped types (Check, Rule, FileMatch, FileTypeDeclaration, ClassifiedFile)
use Pydantic BaseModel — frozen, validated, and self-documenting. The model IS
the schema: use Rule.model_json_schema() to export.

Internal types (LocalFinding, Violation)
remain plain dataclasses — no schema contract needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated, Literal

import regex
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator
from pydantic_core import PydanticCustomError

from reporails_cli.core.platform.contract.json_value import JsonValue
from reporails_cli.core.platform.contract.rule_pattern import compile_rule_pattern
from reporails_cli.core.platform.dto.diagnostics import FindingBase


class Category(str, Enum):
    """Rule categories matching framework."""

    STRUCTURE = "structure"
    COHERENCE = "coherence"
    DIRECTION = "direction"
    EFFICIENCY = "efficiency"
    MAINTENANCE = "maintenance"
    GOVERNANCE = "governance"


# The order rule listings show categories in.
CATEGORY_DISPLAY_ORDER: tuple[Category, ...] = (
    Category.STRUCTURE,
    Category.DIRECTION,
    Category.COHERENCE,
    Category.EFFICIENCY,
    Category.MAINTENANCE,
    Category.GOVERNANCE,
)

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


# Registry severity order, most severe first; INFO is not ranked.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class Level(str, Enum):
    """Project levels from framework."""

    L0 = "L0"  # System
    L1 = "L1"  # Primer
    L2 = "L2"  # Composite
    L3 = "L3"  # Scoped
    L4 = "L4"  # Delegated
    L5 = "L5"  # Abstracted
    L6 = "L6"  # Governed
    L7 = "L7"  # Adaptive


# ---------------------------------------------------------------------------
# Schema-mapped models (Pydantic) — frozen, validated
# ---------------------------------------------------------------------------


class FileTypeDeclaration(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
    """A typed file declaration from agent config file_types section."""

    model_config = ConfigDict(frozen=True)

    name: str  # the config key: "main", "rules", "skills", "agents", …
    patterns: tuple[str, ...]  # glob patterns
    required: bool = False
    properties: dict[str, str | list[str]] = Field(default_factory=dict)
    entry_patterns: tuple[str, ...] = ()  # where an instance's entry file sits (a skill's SKILL.md)


class ClassifiedFile(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
    """A file matched to a type declaration with resolved properties."""

    model_config = ConfigDict(frozen=True)

    path: Path
    file_type: str  # the config key, as FileTypeDeclaration.name
    properties: dict[str, str | list[str]] = Field(default_factory=dict)


class FileMatch(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
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
    loading_verb: list[str] | str | None = None
    link_source_type: list[str] | str | None = None


# The check fields that hold a regex.
REGEX_PATTERN_FIELDS = ("pattern-regex", "pattern-not-regex")
_OPERATORS = ("pattern-regex", "pattern-either", "patterns")


def _compiled(text: str) -> str:
    """`text` when it compiles as a rule pattern; the compile error otherwise."""
    try:
        compile_rule_pattern(text)
    except regex.error as exc:
        raise PydanticCustomError("pattern_compile", "does not compile: {reason}", {"reason": str(exc)}) from exc
    return text


RulePattern = Annotated[str, AfterValidator(_compiled)]


def _item_keys(value: object, owner: str, allowed: tuple[str, ...]) -> object:
    """`value` when it is a mapping of an `owner` item holding exactly one `allowed` key, with a value."""
    if not isinstance(value, dict):
        return value
    found = [str(key) for key in value]
    if len(found) == 1 and found[0] in allowed:
        if value[found[0]] is None:
            raise PydanticCustomError("pattern_item", "`{key}` needs a value", {"key": found[0]})
        return value
    held = ", ".join(f"`{key}`" for key in found) or "nothing"
    expected = "one of " + ", ".join(f"`{name}`" for name in allowed)
    raise PydanticCustomError(
        "pattern_item",
        "holds {held}; an item of `{owner}` holds {expected}",
        {"held": held, "owner": owner, "expected": expected},
    )


class PatternEitherItem(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
    """One alternative of a check's `pattern-either`: a `pattern-regex`."""

    model_config = ConfigDict(frozen=True)

    pattern_regex: RulePattern = Field(alias="pattern-regex")

    @model_validator(mode="before")
    @classmethod
    def _only_regex(cls, value: object) -> object:
        """Refuse an item holding anything but `pattern-regex`."""
        return _item_keys(value, "pattern-either", ("pattern-regex",))


class PatternsItem(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
    """One term of a check's `patterns`: a `pattern-regex` or a `pattern-not-regex`."""

    model_config = ConfigDict(frozen=True)

    pattern_regex: RulePattern | None = Field(default=None, alias="pattern-regex")
    pattern_not_regex: RulePattern | None = Field(default=None, alias="pattern-not-regex")

    @model_validator(mode="before")
    @classmethod
    def _one_regex(cls, value: object) -> object:
        """Refuse an item holding anything but exactly one of the two regex keys."""
        return _item_keys(value, "patterns", REGEX_PATTERN_FIELDS)


class Check(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
    """A specific check within a rule.

    Checks have a type matching their gate: mechanical (Python function),
    deterministic (regex pattern), or content_query (atom-based).
    """

    model_config = ConfigDict(frozen=True)

    id: str  # e.g., "CORE.S.0001.file-exists"
    type: str = "deterministic"  # "mechanical" | "deterministic" | "content_query"
    check: str | None = None  # Mechanical function name
    args: dict[str, JsonValue] | None = None  # Mechanical/content_query arguments
    query: str | None = None  # Content query function name (type=content_query)
    expect: str = "present"  # "present" = no match is violation; "absent" = match is violation
    replaces: str = ""  # Check ID from superseded rule to replace (inheritance)
    severity: Severity | None = None  # Check-level severity override (None = use rule severity)
    message: str = ""  # Check-level message (empty = use check result message)
    # "aggregate": project-aggregate check, skipped under a scoped/narrowed run;
    # "once": one project-wide fact, reported once per project and kept on a narrowed run.
    project_scope: Literal["", "aggregate", "once"] = ""
    convention: bool = False  # Finding names a documentation convention the file does not follow
    # The pattern operator of a deterministic check: exactly one of the three.
    pattern_regex: RulePattern | None = Field(default=None, alias="pattern-regex")
    pattern_either: list[PatternEitherItem] | None = Field(default=None, alias="pattern-either", min_length=1)
    patterns: list[PatternsItem] | None = Field(default=None, min_length=1)

    @model_validator(mode="before")
    @classmethod
    def _one_operator(cls, data: object) -> object:
        """Refuse a check with a misplaced, empty, repeated or missing pattern operator, by its raw keys."""
        if not isinstance(data, dict):
            return data
        kind = data.get("type", cls.__pydantic_fields__["type"].default)
        misplaced = [name for name in (*_OPERATORS, "pattern-not-regex") if name in data]
        if kind != "deterministic" and misplaced:
            raise PydanticCustomError(
                "pattern_operator",
                "{names} is read only on a deterministic check",
                {"names": ", ".join(f"`{name}`" for name in misplaced)},
            )
        if "pattern-not-regex" in data:
            raise PydanticCustomError("pattern_operator", "`pattern-not-regex` is read only inside patterns", {})
        for name in _OPERATORS:
            if name in data and data[name] is None:
                raise PydanticCustomError("pattern_operator", "`{name}` needs a value", {"name": name})
        given = [name for name in _OPERATORS if name in data]
        if len(given) > 1:
            raise PydanticCustomError(
                "pattern_operator",
                "holds more than one pattern operator ({names}); keep one",
                {"names": ", ".join(f"`{name}`" for name in given)},
            )
        if not given and kind == "deterministic":
            raise PydanticCustomError(
                "pattern_operator",
                "a deterministic check needs one pattern operator: pattern-regex, pattern-either or patterns",
                {},
            )
        return data


@dataclass(frozen=True, slots=True)
class FieldProblem:
    """One rejected field of a rule definition: its dotted `field` path, a one-line `message`, and `kind`."""

    field: str
    message: str
    kind: Literal["missing", "invalid"]

    @property
    def text(self) -> str:
        """The problem as one line: `<field>: <message>`, the message alone for a problem of the whole value."""
        return f"{self.field}: {self.message}" if self.field else self.message


class Rule(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
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
    # Operator-facing fix text from rule.md frontmatter.
    fix: str = Field(default="", max_length=1000)
    match: FileMatch | None = None  # Property-based file targeting
    supersedes: str | None = None  # Coordinate of rule this replaces
    inherited: str | None = None  # Coordinate of parent rule to inherit checks from (both stay active)
    depends_on: list[str] = Field(default_factory=list)  # Rule coordinates that must pass first

    # Capability gating
    requires_capability: str | None = None  # Capability ID; rule fires only for agents that have it
    # Per-surface applicable-concern overrides (population deferred)
    surface_mutations: dict[str, JsonValue] | None = None

    # Checks (all rule types)
    checks: list[Check] = Field(default_factory=list)

    # References
    see_also: list[str] = Field(default_factory=list)

    # Paths (set after loading)
    md_path: Path | None = None
    yml_path: Path | None = None


# ---------------------------------------------------------------------------
# Internal types (dataclasses) — no schema contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LocalFinding(FindingBase):
    """A finding from a local check or a client check."""

    source: str = "local"  # "m_probe" | "client_check"
    check_id: str = ""  # specific check that triggered this
    signature: str = ""  # matched text — same secret flagged by two rules shares this, so it counts once


@dataclass(frozen=True)
class LocalEntry:
    """One local finding as the diagnostics request carries it — no message, no matched text.

    `file` is the absolute path, `line` is 0 for a finding about the whole file, and `type` is the file's type
    as its agent's config names it.
    """

    rule: str
    file: str
    line: int
    severity: str
    check: str = ""
    type: str = "generic"


@dataclass(frozen=True)
class Violation:
    """A rule violation found during analysis."""

    rule_id: str  # e.g., "CORE:S:0005"
    rule_title: str  # e.g., "Instruction File Size Limit"
    location: str  # e.g., "CLAUDE.md:45"
    message: str  # From rule definition
    severity: Severity
    check_id: str | None = None  # e.g., "CORE:S:0005:check:0001"
    fix: str = ""  # Canonical fix text propagated from Rule.fix


__all__ = [
    "CATEGORY_CODES",
    "CATEGORY_DISPLAY_ORDER",
    "SEVERITY_ORDER",
    "Category",
    "Check",
    "ClassifiedFile",
    "FileMatch",
    "FileTypeDeclaration",
    "Level",
    "Rule",
    "RuleType",
    "Severity",
    "Violation",
]
