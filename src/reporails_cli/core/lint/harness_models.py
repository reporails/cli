"""Data models for the rule-test harness.

The dataclasses the harness threads through discovery, running, scoring, and
linting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from reporails_cli.core.platform.dto.models import Check

CASE_PREFIXES = ("pass-", "fail-")
_FIXTURE_EXCLUDES = frozenset({".gitkeep", ".DS_Store"})


class HarnessStatus(str, Enum):
    """Rule-level harness outcomes."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_IMPLEMENTED = "not_implemented"
    NO_FIXTURES = "no_fixtures"
    SKIPPED = "skipped"


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


class RuleInfo(BaseModel):
    """Lightweight rule descriptor for harness discovery.

    A pydantic model so a `checks=[{...}]` construction coerces each dict to a
    `Check` and a schema-invalid entry fails loudly at construction. `match` stays
    an open dict — its values are not further constrained here.
    """

    rule_id: str
    slug: str
    title: str
    category: str
    rule_type: str
    match: dict[str, Any]
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
    # Set when the rule's check definitions could not be read: names the file and what is wrong.
    load_error: str = ""

    @property
    def has_checks(self) -> bool:
        """Whether the rule has any check definitions."""
        return len(self.checks) > 0

    @property
    def has_pass_fixture(self) -> bool:
        """Whether the rule has a non-empty pass fixture directory."""
        d = self.rule_dir / "tests" / "pass"
        return d.is_dir() and any(d.iterdir())

    @property
    def has_fail_fixture(self) -> bool:
        """Whether the rule has a non-empty fail fixture directory."""
        d = self.rule_dir / "tests" / "fail"
        return d.is_dir() and any(d.iterdir())

    def fixture_cases(self) -> tuple[list[tuple[str, Path]], list[str]]:
        """Split `tests/cases/` into runnable and unrunnable entries.

        Returns `(runnable, not_run)`: `runnable` is `(name, directory)` for each non-empty
        `pass-*` / `fail-*` directory, sorted by name; `not_run` names every other entry.
        """
        cases_dir = self.rule_dir / "tests" / "cases"
        runnable: list[tuple[str, Path]] = []
        not_run: list[str] = []
        if not cases_dir.is_dir():
            return runnable, not_run
        for entry in sorted(cases_dir.iterdir()):
            if entry.name in _FIXTURE_EXCLUDES:
                continue
            if entry.is_dir() and entry.name.startswith(CASE_PREFIXES) and any(entry.iterdir()):
                runnable.append((entry.name, entry))
            else:
                not_run.append(entry.name)
        return runnable, not_run

    @property
    def has_cases(self) -> bool:
        """Whether the rule has any runnable `tests/cases/pass-*` or `fail-*` directory."""
        return bool(self.fixture_cases()[0])


@dataclass
class ScoreDelta:
    """Per-rule quality delta between pass and fail fixtures."""

    rule_id: str
    slug: str
    pass_score: float
    fail_score: float
    delta: float


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
