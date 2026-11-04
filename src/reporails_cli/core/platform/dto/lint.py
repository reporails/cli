"""Shapes of the lint tests: content-query results, compiled regex checks and the rule-test harness."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import regex as re
from pydantic import BaseModel, Field

from reporails_cli.core.platform.dto.diagnostics import FindingSeverity
from reporails_cli.core.platform.dto.models import Check, FieldProblem


@dataclass(frozen=True)
class QueryResult:
    """Result of a content query against RulesetMap atoms."""

    found: bool
    file: str = ""
    line: int = 0
    evidence: str = ""
    # Every match in the file, in line order, for a query that reports each one; the result
    # itself then stands for the first. Empty for a query that reports one match.
    matches: tuple[QueryResult, ...] = ()


@dataclass
class CheckRun:
    """Result of one check against one fixture."""

    check_id: str
    check_type: str
    fixture: str  # "pass", "fail", or "case <name>"
    passed: bool
    message: str


@dataclass
class HarnessResult:
    """Per-rule harness outcome."""

    rule_id: str
    slug: str
    title: str
    status: str  # HarnessStatus value
    check_runs: list[CheckRun] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    cases_run: list[str] = field(default_factory=list)  # names of the tests/cases directories that ran
    cases_not_run: list[str] = field(default_factory=list)  # case directories with an unrecognised name or no files


class RuleInfo(BaseModel):  # type: ignore[explicit-any]  # pydantic: BaseModel.__init__ takes **data: Any
    """Lightweight rule descriptor for harness discovery.

    A pydantic model so a `checks=[{...}]` construction coerces each dict to a
    `Check` and a schema-invalid entry fails loudly at construction.
    """

    rule_id: str
    slug: str
    title: str
    category: str
    checks: list[Check]
    rule_dir: Path
    checks_yml: Path
    supersedes: str = ""  # Coordinate of a parent rule whose checks this rule inherits and replaces
    inherited: str = ""  # Coordinate of a parent rule whose checks this rule inherits (both stay active)
    # check.id -> the checks.yml a merged-in inherited check's pattern actually lives in
    # (the parent's, not this rule's own `checks_yml`). Populated by `apply_check_inheritance`;
    # a `deterministic` check looks its pattern up by id in a single checks.yml file, so an
    # inherited check must resolve against its origin file, not the child's.
    inherited_checks_yml: dict[str, Path] = Field(default_factory=dict)
    # What the rule.md frontmatter declares, for the structural lint.
    frontmatter_read: bool = False  # a frontmatter mapping was recovered from rule.md
    severity_declared: bool = False
    enforcement_required: bool = False
    enforcement_mechanism_named: bool = False
    # Set when the rule's check definitions could not be read: names the file and what is wrong.
    load_error: str = ""
    # The rule.md fields the build rejected, one record each, and the rule.md path they are reported under.
    field_problems: tuple[FieldProblem, ...] = ()
    rule_md_label: str = ""

    @property
    def load_failure(self) -> str:
        """Why the rule cannot run: its load error and one line per rejected field; empty when it loads."""
        lines = [self.load_error] if self.load_error else []
        lines.extend(f"{self.rule_md_label}: {p.text}" for p in self.field_problems)
        return "\n".join(lines)

    @property
    def rejected_fields(self) -> frozenset[str]:
        """The top-level rule.md field names the build rejected."""
        return frozenset(p.field.split(".")[0] for p in self.field_problems)

    @property
    def has_checks(self) -> bool:
        """Whether the rule has any check definitions."""
        return len(self.checks) > 0


@dataclass
class LintError:
    """A structural integrity error found in a rule."""

    rule_id: str
    check_name: str
    message: str


@dataclass
class BaselineEntry:
    """A single entry in the expected-rules baseline."""

    rule_id: str
    slug: str
    has_fixtures: bool


@dataclass
class CoverageGap:
    """A rule expected in the baseline but missing or lacking fixtures."""

    rule_id: str
    reason: str


@dataclass(frozen=True)
class CompiledCheck:
    """A single compiled regex check from a YAML rule file."""

    id: str
    message: str
    severity: FindingSeverity
    patterns: tuple[re.Pattern[str], ...]  # AND — all must match
    negative_patterns: tuple[re.Pattern[str], ...]  # AND — none must match
    either_patterns: tuple[re.Pattern[str], ...]  # OR — any must match
    path_includes: tuple[str, ...]  # Resolved path filters
    every_match: bool = False  # True → report every matching line, not the first (a check that forbids something)
    follow_imports: bool = False  # True → also read the text an `@path` import splices in, reporting at its source
    entry_only: bool = False  # True → only a skill's entry file is checked, once the run records skills
    min_lines: int = 0  # > 0 → a file shorter than this many lines is neither failing nor passing the check


@dataclass
class CompiledRuleSet:
    """All compiled checks from a set of YAML rule files."""

    checks: list[CompiledCheck] = field(default_factory=list)


@dataclass(frozen=True)
class ScanOutcome:
    """What a scan found, for the checks to be judged against (see `emit_expect_findings`)."""

    matched_pairs: set[tuple[str, str]]
    match_details: dict[tuple[str, str], list[tuple[int, str, str]]]
    scanned_files: list[str]
    scan_root: Path | None = None
    fix_by_rule: dict[str, str] = field(default_factory=dict)
    skill_entries: set[Path] | None = None
    not_evaluated: set[tuple[str, str]] = field(default_factory=set)
