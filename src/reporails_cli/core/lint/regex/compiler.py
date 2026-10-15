"""YAML rule file → compiled regex checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from pathlib import Path

import regex as re
import yaml

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_list, as_object, str_list
from reporails_cli.core.platform.dto.diagnostics import FindingSeverity
from reporails_cli.core.platform.dto.models import Severity
from reporails_cli.core.platform.utils.utils import load_yaml_file

logger = logging.getLogger(__name__)

# Pattern operators we support
_SUPPORTED_OPERATORS = {"pattern-regex", "pattern-either", "patterns"}


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
    skipped: list[str] = field(default_factory=list)


def _compile_pattern(pattern_str: str) -> re.Pattern[str]:
    """Compile a regex pattern string with MULTILINE and DOTALL flags."""
    return re.compile(pattern_str, re.MULTILINE | re.DOTALL)


def _pattern_text(value: JsonValue) -> re.Pattern[str]:
    """Compile a `pattern-regex` / `pattern-not-regex` value; a value that is not a string is an invalid regex."""
    if not isinstance(value, str):
        raise re.error("a pattern must be a string")
    return _compile_pattern(value)


def _text(rule_entry: JsonObject, key: str, default: str) -> str:
    """The string a rule entry holds under `key`, `default` when it holds none."""
    value = rule_entry.get(key)
    return value if isinstance(value, str) else default


def _get_operator(rule_entry: JsonObject) -> str | None:
    """Identify which pattern operator a rule entry uses."""
    if "pattern-regex" in rule_entry:
        return "pattern-regex"
    if "pattern-either" in rule_entry:
        return "pattern-either"
    if "patterns" in rule_entry:
        return "patterns"
    return None


def display_severity(raw: str) -> FindingSeverity:
    """Normalize a severity to the display vocabulary (`error` / `warning` / `info`).

    `Rule.severity` and `Check.severity` carry the SARIF-adjacent
    `critical`/`high`/`medium`/`low`/`info` vocabulary; the merger and
    text formatters only count `error`/`warning`/`info`. A check file may
    also say `error`.
    """
    if raw == "error" or raw in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if raw in (Severity.LOW, Severity.INFO):
        return "info"
    return "warning"


def _min_lines(rule_entry: JsonObject) -> int:
    """A check's `min_lines` gate, 0 when it declares none or a non-positive one."""
    value = rule_entry.get("min_lines")
    return int(value) if isinstance(value, (int, float)) and value > 0 else 0


def _compile_single_rule(rule_entry: JsonObject) -> CompiledCheck | None:
    """Compile a single YAML rule entry into a CompiledCheck, with its reporting flags.

    A check that forbids something (`expect: absent`) reports every match; `follow_imports: true`
    makes a check read imported text as well; `min_lines` gates it to files of at least that length;
    `entry_only: true` limits it to a skill's entry file.
    Returns None if the rule uses unsupported operators.
    """
    check = _compile_operator(rule_entry)
    if check is None:
        return None
    return replace(
        check,
        every_match=rule_entry.get("expect") == "absent",
        follow_imports=rule_entry.get("follow_imports") is True,
        min_lines=_min_lines(rule_entry),
        entry_only=rule_entry.get("entry_only") is True,
    )


def _compile_operator(rule_entry: JsonObject) -> CompiledCheck | None:
    """Compile a rule entry's pattern operator into a CompiledCheck. None for an unsupported one."""
    rule_id = _text(rule_entry, "id", "unknown")
    message = _text(rule_entry, "message", "")
    severity = display_severity(_text(rule_entry, "severity", "WARNING").lower())

    # Extract path filters
    path_includes = tuple(str_list(as_object(rule_entry.get("paths")).get("include")))

    operator = _get_operator(rule_entry)

    if operator == "pattern-regex":
        compiled = _pattern_text(rule_entry["pattern-regex"])
        return CompiledCheck(
            id=rule_id,
            message=message,
            severity=severity,
            patterns=(compiled,),
            negative_patterns=(),
            either_patterns=(),
            path_includes=path_includes,
        )

    if operator == "pattern-either":
        compiled_either = []
        for item in as_list(rule_entry["pattern-either"]):
            if isinstance(item, dict) and "pattern-regex" in item:
                compiled_either.append(_pattern_text(item["pattern-regex"]))
            else:
                logger.warning("Unsupported sub-operator in pattern-either for rule %s", rule_id)
        if not compiled_either:
            return None
        return CompiledCheck(
            id=rule_id,
            message=message,
            severity=severity,
            patterns=(),
            negative_patterns=(),
            either_patterns=tuple(compiled_either),
            path_includes=path_includes,
        )

    if operator == "patterns":
        positive = []
        negative = []
        for item in as_list(rule_entry["patterns"]):
            if isinstance(item, dict) and "pattern-regex" in item:
                positive.append(_pattern_text(item["pattern-regex"]))
            elif isinstance(item, dict) and "pattern-not-regex" in item:
                negative.append(_pattern_text(item["pattern-not-regex"]))
            else:
                logger.warning("Unsupported sub-operator in patterns block for rule %s", rule_id)
        if not positive and not negative:
            return None
        return CompiledCheck(
            id=rule_id,
            message=message,
            severity=severity,
            patterns=tuple(positive),
            negative_patterns=tuple(negative),
            either_patterns=(),
            path_includes=path_includes,
        )

    return None


def _parse_entries(data: JsonObject, yml_path: Path) -> list[JsonObject] | None:
    """Extract deterministic entries from YAML data ('checks' key)."""
    entries = data.get("checks")
    if not isinstance(entries, list):
        logger.warning("Rule file %s has no valid 'checks' list, skipping", yml_path)
        return None
    return [e for e in entries if isinstance(e, dict) and e.get("type", "deterministic") == "deterministic"]


def _compile_entries(
    entries: list[JsonObject],
    result: CompiledRuleSet,
) -> None:
    """Compile each entry into `result`; an entry that cannot be compiled is recorded as skipped."""
    for rule_entry in entries:
        rule_id = _text(rule_entry, "id", "unknown")
        if _get_operator(rule_entry) is None:
            logger.warning("Rule %s has no recognized pattern operator, skipping", rule_id)
            result.skipped.append(rule_id)
            continue

        try:
            check = _compile_single_rule(rule_entry)
        except re.error as e:
            logger.warning("Invalid regex in rule %s: %s", rule_id, e)
            result.skipped.append(rule_id)
            continue
        if check is None:
            result.skipped.append(rule_id)
            continue
        result.checks.append(check)


def compile_rules(yml_paths: list[Path]) -> CompiledRuleSet:
    """Compile YAML rule files into a CompiledRuleSet.

    Args:
        yml_paths: Paths to YAML rule files

    Returns:
        CompiledRuleSet with compiled checks and skipped rule IDs
    """
    result = CompiledRuleSet()

    for yml_path in yml_paths:
        if not yml_path.exists():
            continue

        try:
            data = load_yaml_file(yml_path)
            if not isinstance(data, dict) or not data:
                logger.warning("Rule file %s has no valid data, skipping", yml_path)
                continue

            entries = _parse_entries(data, yml_path)
            if entries is None:
                continue

            _compile_entries(entries, result)

        except (yaml.YAMLError, OSError, UnicodeDecodeError) as e:
            logger.warning("Failed to load rule file %s: %s", yml_path, e)

    return result
