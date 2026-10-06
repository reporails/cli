"""Content-quality checker — dispatches rule checks as atom queries.

Replaces deterministic regex scanning for content-quality rules.
Each rule with type=content_query checks is dispatched to the
corresponding query function in content_queries.py.

Queries run against files matching the rule's `match` field.
A check that requires something emits one finding per rule; a check that forbids something emits
one per place it finds it.
"""

from __future__ import annotations

import logging
from typing import Any

from reporails_cli.core.lint.content_queries import QUERY_REGISTRY
from reporails_cli.core.lint.regex.compiler import display_severity
from reporails_cli.core.platform.dto.models import ClassifiedFile, FileMatch, LocalFinding, Rule
from reporails_cli.core.platform.dto.ruleset import RulesetMap

logger = logging.getLogger(__name__)


def _matching_files(
    ruleset_map: RulesetMap,
    classified: list[ClassifiedFile],
    match: FileMatch | None,
) -> list[str]:
    """Return file paths from the ruleset that match the rule's targeting criteria."""
    rm_paths = {fr.path for fr in ruleset_map.files}

    if match is None:
        return sorted(rm_paths)

    from reporails_cli.core.platform.policy.matching import file_matches, is_wildcard_match

    matched = [cf.path.as_posix() for cf in classified if file_matches(cf, match) and cf.path.as_posix() in rm_paths]
    if matched:
        return sorted(matched)
    # Don't fall back to all files when the match names ANY criterion — a config
    # rule shouldn't fire on memory files just because no config exists, and a
    # `match: {format: freeform}` prose rule must not score a `schema_validated`
    # JSON/TOML surface just because the project has no freeform file in the
    # scope. Only a fully-wildcard `match: {}` falls back to every mapped file.
    if not is_wildcard_match(match):
        return []
    return sorted(rm_paths)


def _evaluate_check(
    ruleset_map: RulesetMap,
    check: Any,
    rule: Rule,
    classified: list[ClassifiedFile],
) -> list[LocalFinding]:
    """Evaluate a single content_query check. Returns its findings: one for a check that requires
    something and finds it missing, one per match for a check that forbids something."""
    query_fn = QUERY_REGISTRY.get(check.query)
    if query_fn is None:
        logger.warning("Unknown content query: %s (check %s)", check.query, check.id)
        return []

    check_args: dict[str, Any] = dict(check.args or {})
    target_files = _matching_files(ruleset_map, classified, rule.match)
    if not target_files:
        return []

    results = [r for r in (query_fn(ruleset_map, fp, **check_args) for fp in target_files) if r.found]
    if check.expect == "present" and results:
        return []
    if check.expect != "present" and not results:
        return []

    message = check_args.get("message", "")
    if not message:
        message = f"Content check failed: {check.query} (expect={check.expect})"

    # A check that forbids something reports each place the query found it; a check that requires
    # something has nothing to point at, so it reports the file.
    if check.expect == "present":
        return [_finding(rule, check, message, target_files[0], 1)]
    return [
        _finding(rule, check, message.replace("{text}", hit.evidence), hit.file or target_files[0], hit.line or 1)
        for result in results
        for hit in (result.matches or (result,))
    ]


def _finding(rule: Rule, check: Any, message: str, file: str, line: int) -> LocalFinding:
    """A rule's content-check finding at `file`:`line`."""
    return LocalFinding(
        file=_relative_path(file),
        line=line,
        severity=display_severity(rule.severity.value),
        rule=rule.id,
        message=message,
        fix=rule.fix,
        source="content_query",
        check_id=check.id,
    )


def run_content_checks(
    ruleset_map: RulesetMap,
    rules: dict[str, Rule],
    classified: list[ClassifiedFile] | None = None,
) -> list[LocalFinding]:
    """Run content-quality checks against RulesetMap atoms.

    Each content_query check tests whether the matched files have the
    required content.
    """
    if classified is None:
        classified = []

    findings: list[LocalFinding] = []

    for rule in rules.values():
        for check in rule.checks:
            if check.type != "content_query" or not check.query:
                continue
            findings.extend(_evaluate_check(ruleset_map, check, rule, classified))

    return findings


def _relative_path(file_path: str) -> str:
    """Normalize file path for display. Uses merger's normalize_finding_path."""
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    return normalize_finding_path(file_path)
