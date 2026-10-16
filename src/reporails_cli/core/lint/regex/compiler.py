"""YAML rule file → compiled regex checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import regex as re

from reporails_cli.core.platform.adapters.registry import RuleReadError, read_checks_document
from reporails_cli.core.platform.adapters.rule_builder import load_checks
from reporails_cli.core.platform.contract.json_value import JsonObject, as_list, as_object, str_list
from reporails_cli.core.platform.contract.rule_pattern import compile_rule_pattern
from reporails_cli.core.platform.dto.diagnostics import FindingSeverity
from reporails_cli.core.platform.dto.models import Check, Severity

logger = logging.getLogger(__name__)


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


def display_severity(raw: str) -> FindingSeverity:
    """Normalize a severity to the display vocabulary (`error` / `warning` / `info`).

    `Rule.severity` and `Check.severity` carry the SARIF-adjacent
    `critical`/`high`/`medium`/`low`/`info` vocabulary; the merger and
    text formatters only count `error`/`warning`/`info`.
    """
    if raw in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if raw in (Severity.LOW, Severity.INFO):
        return "info"
    return "warning"


def _min_lines(rule_entry: JsonObject) -> int:
    """A check's `min_lines` gate, 0 when it declares none or a non-positive one."""
    value = rule_entry.get("min_lines")
    return int(value) if isinstance(value, (int, float)) and value > 0 else 0


def _compile_check(check: Check, rule_entry: JsonObject) -> CompiledCheck:
    """Compile a deterministic check into a CompiledCheck, with its reporting flags.

    A check that forbids something (`expect: absent`) reports every match; `follow_imports: true`
    makes a check read imported text as well; `min_lines` gates it to files of at least that length;
    `entry_only: true` limits it to a skill's entry file.
    """
    positive: list[str] = []
    negative: list[str] = []
    if check.pattern_regex is not None:
        positive = [check.pattern_regex]
    elif check.patterns:
        positive = [item.pattern_regex for item in check.patterns if item.pattern_regex is not None]
        negative = [item.pattern_not_regex for item in check.patterns if item.pattern_not_regex is not None]
    return CompiledCheck(
        id=check.id,
        message=check.message,
        severity=display_severity(check.severity.value if check.severity else "warning"),
        patterns=tuple(compile_rule_pattern(text) for text in positive),
        negative_patterns=tuple(compile_rule_pattern(text) for text in negative),
        either_patterns=tuple(compile_rule_pattern(item.pattern_regex) for item in check.pattern_either or []),
        path_includes=tuple(str_list(as_object(rule_entry.get("paths")).get("include"))),
        every_match=check.expect == "absent",
        follow_imports=rule_entry.get("follow_imports") is True,
        min_lines=_min_lines(rule_entry),
        entry_only=rule_entry.get("entry_only") is True,
    )


def compile_rules(yml_paths: list[Path]) -> CompiledRuleSet:
    """Compile YAML rule files into a CompiledRuleSet.

    A file that cannot be read, or whose checks do not load, is logged and left out.

    Args:
        yml_paths: Paths to YAML rule files

    Returns:
        CompiledRuleSet with the compiled deterministic checks
    """
    result = CompiledRuleSet()

    for yml_path in yml_paths:
        if not yml_path.exists():
            continue

        try:
            data = read_checks_document(yml_path)
            if not data:
                logger.warning("Rule file %s has no valid data, skipping", yml_path)
                continue
            if not isinstance(data.get("checks"), list):
                logger.warning("Rule file %s has no valid 'checks' list, skipping", yml_path)
                continue
            checks = load_checks(data)
        except (RuleReadError, ValueError) as e:
            logger.warning(
                "Failed to load rule file %s: %s", yml_path, e.problem if isinstance(e, RuleReadError) else e
            )
            continue

        result.checks.extend(
            _compile_check(check, as_object(entry))
            for check, entry in zip(checks, as_list(data.get("checks")), strict=True)
            if check.type == "deterministic"
        )

    return result
