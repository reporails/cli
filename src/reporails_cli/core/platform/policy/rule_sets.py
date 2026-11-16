"""Rule sets: id sets and the dependency map derived from resolved rules. Pure over the rules given."""

from __future__ import annotations

from collections.abc import Mapping

from reporails_cli.core.platform.dto.models import Rule


def file_level_ids(rules: Mapping[str, Rule]) -> frozenset[str]:
    """Ids of the content checks of `rules` that require something in a file."""
    return frozenset(
        check.id
        for rule in rules.values()
        for check in rule.checks
        if check.type == "content_query" and check.expect == "present" and check.id
    )


def convention_check_ids(rules: Mapping[str, Rule]) -> frozenset[str]:
    """Ids of the checks of `rules` flagged `convention: true`: their finding names a missing convention."""
    return frozenset(check.id for rule in rules.values() for check in rule.checks if check.convention and check.id)


def whole_run_check_ids(rules: Mapping[str, Rule]) -> frozenset[str]:
    """Ids of the checks of `rules` whose finding stands for the matched files as a whole.

    These are the content checks that require something in a file and the project-aggregate
    checks: neither points at one file or line.
    """
    return file_level_ids(rules) | frozenset(
        check.id for rule in rules.values() for check in rule.checks if check.project_scope and check.id
    )


def rule_dependencies(rules: Mapping[str, Rule]) -> dict[str, frozenset[str]]:
    """`{rule id: the rule ids it depends on}` across `rules`, resolved through supersession.

    A dependency on a rule an agent rule supersedes names the superseding rule, which carries
    the findings under its own id.
    """
    successor = {r.supersedes: rid for rid, r in rules.items() if r.supersedes}
    return {
        rid: frozenset(successor.get(dep, dep) for dep in rule.depends_on)
        for rid, rule in rules.items()
        if rule.depends_on
    }
