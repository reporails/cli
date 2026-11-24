"""YAML rule file → compiled regex checks."""

from __future__ import annotations

from collections.abc import Iterable

from reporails_cli.core.lint.regex.not_evaluated import rule_id_of
from reporails_cli.core.platform.contract.rule_pattern import compile_rule_pattern
from reporails_cli.core.platform.dto.diagnostics import FindingSeverity
from reporails_cli.core.platform.dto.lint import CompiledCheck, CompiledRuleSet
from reporails_cli.core.platform.dto.models import Check, Rule, Severity


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


def compile_check(check: Check) -> CompiledCheck:
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
        path_includes=tuple(check.paths.include) if check.paths else (),
        every_match=check.expect == "absent",
        follow_imports=check.follow_imports,
        min_lines=check.min_lines or 0,
        entry_only=check.entry_only,
    )


def compile_rules(rules: Iterable[Rule]) -> CompiledRuleSet:
    """Compile each rule's own deterministic checks into a CompiledRuleSet.

    A check whose id names another rule is skipped; that rule compiles it.
    """
    return CompiledRuleSet(
        checks=[
            compile_check(check)
            for rule in rules
            for check in rule.checks
            if check.type == "deterministic" and rule_id_of(check.id) == rule.id
        ]
    )
