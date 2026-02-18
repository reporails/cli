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

from reporails_cli.core.templates import TEMPLATE_PATTERN, resolve_templates_str

# Use C YAML loader when available
try:
    from yaml import CSafeLoader as _YamlLoader
except ImportError:
    from yaml import SafeLoader as _YamlLoader  # type: ignore[assignment]

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
    path_includes = tuple(paths_config.get("include") or [])

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
            # Read file once — check for templates in memory (avoids double-read)
            raw_content = yml_path.read_text(encoding="utf-8")
            if template_context and TEMPLATE_PATTERN.search(raw_content):
                content = resolve_templates_str(raw_content, template_context)
            else:
                content = raw_content

            data = yaml.load(content, Loader=_YamlLoader)
            if not data or "rules" not in data or not isinstance(data["rules"], list):
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


# Maximum named groups per combined regex (Python re limit is ~100)
_MAX_GROUPS_PER_BATCH = 99


_INLINE_FLAGS_RE = re.compile(r"^\(\?([aiLmsux]+)\)")


def _scope_inline_flags(pattern: str) -> str:
    """Convert global inline flags to scoped flags for embedding in named groups.

    Transforms ``(?i)pattern`` → ``(?i:pattern)`` so the flag is scoped to the
    enclosing named group instead of being a global flag (which Python rejects
    when not at position 0).
    """
    m = _INLINE_FLAGS_RE.match(pattern)
    if m:
        flags = m.group(1)
        rest = pattern[m.end() :]
        return f"(?{flags}:{rest})"
    return pattern


def _get_combinable_pattern(check: CompiledCheck) -> str | None:
    """Get a single embeddable pattern string for combined regex batching.

    Returns None if the check cannot be combined (e.g., has negative patterns
    or multiple AND patterns). Handles:
    - Single patterns (with or without inline flags like (?i))
    - Either-pattern alternatives (joined as alternation)
    """
    if check.negative_patterns:
        return None  # Can't batch negatives (require all-must-not-match logic)

    if check.patterns and not check.either_patterns:
        if len(check.patterns) == 1:
            return _scope_inline_flags(check.patterns[0].pattern)
        return None  # Multiple AND patterns can't be combined into alternation

    if check.either_patterns and not check.patterns:
        parts = [_scope_inline_flags(p.pattern) for p in check.either_patterns]
        return "|".join(f"(?:{p})" for p in parts)

    return None


@dataclass(frozen=True)
class CombinedPattern:
    """A batched alternation of checks with named groups."""

    regex: re.Pattern[str]
    group_to_check: dict[str, CompiledCheck]


def build_combined_patterns(
    checks: list[CompiledCheck],
) -> tuple[list[CombinedPattern], list[CompiledCheck]]:
    """Combine eligible checks into batched alternation patterns with named groups.

    Accepts single-pattern checks (with or without inline flags) and
    either-pattern checks. Checks with negative patterns or multiple AND
    patterns are returned as remaining individual checks.

    Args:
        checks: List of compiled checks to partition

    Returns:
        Tuple of (combined_patterns, remaining_individual_checks)
    """
    combinable: list[tuple[CompiledCheck, str]] = []
    remaining: list[CompiledCheck] = []

    for check in checks:
        pat = _get_combinable_pattern(check)
        if pat is not None:
            combinable.append((check, pat))
        else:
            remaining.append(check)

    if not combinable:
        return [], remaining

    combined: list[CombinedPattern] = []
    for batch_start in range(0, len(combinable), _MAX_GROUPS_PER_BATCH):
        batch = combinable[batch_start : batch_start + _MAX_GROUPS_PER_BATCH]
        parts: list[str] = []
        group_map: dict[str, CompiledCheck] = {}
        for i, (check, pat) in enumerate(batch):
            group_name = f"g{i}"
            parts.append(f"(?P<{group_name}>{pat})")
            group_map[group_name] = check
        try:
            combined_re = re.compile("|".join(parts), re.MULTILINE | re.DOTALL)
            combined.append(CombinedPattern(regex=combined_re, group_to_check=group_map))
        except re.error as e:
            logger.warning("Failed to build combined pattern: %s", e)
            remaining.extend(check for check, _ in batch)
    return combined, remaining
