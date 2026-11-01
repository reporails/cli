"""Data models for the rule-test harness.

The dataclasses the harness threads through discovery, running, scoring, and
linting.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from reporails_cli.core.platform.dto.lint import RuleInfo

CASE_PREFIXES = ("pass-", "fail-")
_FIXTURE_EXCLUDES = frozenset({".gitkeep", ".DS_Store"})


class HarnessStatus(str, Enum):
    """Rule-level harness outcomes."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_IMPLEMENTED = "not_implemented"
    NO_FIXTURES = "no_fixtures"
    SKIPPED = "skipped"


def has_pass_fixture(rule: RuleInfo) -> bool:
    """Whether the rule has a non-empty pass fixture directory."""
    d = rule.rule_dir / "tests" / "pass"
    return d.is_dir() and any(d.iterdir())


def has_fail_fixture(rule: RuleInfo) -> bool:
    """Whether the rule has a non-empty fail fixture directory."""
    d = rule.rule_dir / "tests" / "fail"
    return d.is_dir() and any(d.iterdir())


def fixture_cases(rule: RuleInfo) -> tuple[list[tuple[str, Path]], list[str]]:
    """Split `tests/cases/` into runnable and unrunnable entries.

    Returns `(runnable, not_run)`: `runnable` is `(name, directory)` for each non-empty
    `pass-*` / `fail-*` directory, sorted by name; `not_run` names every other entry.
    """
    cases_dir = rule.rule_dir / "tests" / "cases"
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


def has_cases(rule: RuleInfo) -> bool:
    """Whether the rule has any runnable `tests/cases/pass-*` or `fail-*` directory."""
    return bool(fixture_cases(rule)[0])
