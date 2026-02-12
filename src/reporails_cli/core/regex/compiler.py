"""YAML rule file → compiled regex checks.

Parses OpenGrep-compatible YAML rule files and compiles regex patterns
for execution by the runner module.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.templates import has_templates, resolve_templates

logger = logging.getLogger(__name__)

# Pattern operators we support
_SUPPORTED_OPERATORS = {"pattern-regex", "pattern-either", "patterns"}


@dataclass(frozen=True)
class CompiledCheck:
    """A single compiled regex check from a YAML rule file."""

    id: str
    message: str
    severity: str  # "error" | "warning"
    patterns: tuple[re.Pattern[str], ...]  # AND — all must match
    negative_patterns: tuple[re.Pattern[str], ...]  # AND — none must match
    either_patterns: tuple[re.Pattern[str], ...]  # OR — any must match
    path_includes: tuple[str, ...]  # Resolved path filters


@dataclass
class CompiledRuleSet:
    """All compiled checks from a set of YAML rule files."""

    checks: list[CompiledCheck] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def _compile_pattern(pattern_str: str) -> re.Pattern[str]:
    """Compile a regex pattern string with MULTILINE and DOTALL flags."""
    return re.compile(pattern_str, re.MULTILINE | re.DOTALL)


def _get_operator(rule_entry: dict[str, Any]) -> str | None:
    """Identify which pattern operator a rule entry uses."""
    if "pattern-regex" in rule_entry:
        return "pattern-regex"
    if "pattern-either" in rule_entry:
        return "pattern-either"
    if "patterns" in rule_entry:
        return "patterns"
    return None


def _compile_single_rule(rule_entry: dict[str, Any]) -> CompiledCheck | None:
    """Compile a single YAML rule entry into a CompiledCheck.

    Returns None if the rule uses unsupported operators.
    """
    rule_id = rule_entry.get("id", "unknown")
    message = rule_entry.get("message", "")
    severity = rule_entry.get("severity", "WARNING").lower()

    # Normalize severity to SARIF levels
    severity = "error" if severity in ("error", "critical", "high") else "warning"

    # Extract path filters
    paths_config = rule_entry.get("paths", {})
    path_includes = tuple(paths_config.get("include", []))

    operator = _get_operator(rule_entry)

    if operator == "pattern-regex":
        pattern_str = rule_entry["pattern-regex"]
        compiled = _compile_pattern(pattern_str)
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
        either_list = rule_entry["pattern-either"]
        compiled_either = []
        for item in either_list:
            if "pattern-regex" in item:
                compiled_either.append(_compile_pattern(item["pattern-regex"]))
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
        patterns_list = rule_entry["patterns"]
        positive = []
        negative = []
        for item in patterns_list:
            if "pattern-regex" in item:
                positive.append(_compile_pattern(item["pattern-regex"]))
            elif "pattern-not-regex" in item:
                negative.append(_compile_pattern(item["pattern-not-regex"]))
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


def compile_rules(
    yml_paths: list[Path],
    template_context: dict[str, str | list[str]] | None = None,
) -> CompiledRuleSet:
    """Compile YAML rule files into a CompiledRuleSet.

    Args:
        yml_paths: Paths to YAML rule files
        template_context: Template variables for {{placeholder}} resolution

    Returns:
        CompiledRuleSet with compiled checks and skipped rule IDs
    """
    result = CompiledRuleSet()

    for yml_path in yml_paths:
        if not yml_path.exists():
            continue

        try:
            # Resolve templates if needed
            if template_context and has_templates(yml_path):
                content = resolve_templates(yml_path, template_context)
            else:
                content = yml_path.read_text(encoding="utf-8")

            data = yaml.safe_load(content)
            if not data or "rules" not in data:
                continue

            for rule_entry in data["rules"]:
                rule_id = rule_entry.get("id", "unknown")
                operator = _get_operator(rule_entry)

                if operator is None:
                    logger.warning(
                        "Rule %s has no recognized pattern operator, skipping",
                        rule_id,
                    )
                    result.skipped.append(rule_id)
                    continue

                try:
                    check = _compile_single_rule(rule_entry)
                    if check is not None:
                        result.checks.append(check)
                    else:
                        result.skipped.append(rule_id)
                except re.error as e:
                    logger.warning("Invalid regex in rule %s: %s", rule_id, e)
                    result.skipped.append(rule_id)

        except (yaml.YAMLError, OSError, UnicodeDecodeError) as e:
            logger.warning("Failed to load rule file %s: %s", yml_path, e)

    return result
