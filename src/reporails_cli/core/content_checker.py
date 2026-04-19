"""Content-quality checker — dispatches rule checks as atom queries.

Replaces deterministic regex scanning for content-quality rules.
Each rule with type=content_query checks is dispatched to the
corresponding query function in content_queries.py.

Queries run against files matching the rule's `match` field.
A finding is emitted once per rule, not per file.
"""

from __future__ import annotations

import logging
from typing import Any

from reporails_cli.core.content_queries import QUERY_REGISTRY
from reporails_cli.core.mapper.mapper import RulesetMap
from reporails_cli.core.models import ClassifiedFile, FileMatch, LocalFinding, Rule

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

    from reporails_cli.core.classification import file_matches

    matched = [str(cf.path) for cf in classified if file_matches(cf, match) and str(cf.path) in rm_paths]
    # Don't fall back to all files when a specific match type is set —
    # a config rule shouldn't fire on memory files just because no config exists.
    if matched:
        return sorted(matched)
    if match.type is not None:
        return []  # No files of this type — skip, don't fall back
    return sorted(rm_paths)


def _evaluate_check(
    ruleset_map: RulesetMap,
    check: Any,
    rule: Rule,
    classified: list[ClassifiedFile],
    primary_file: str,
) -> LocalFinding | None:
    """Evaluate a single content_query check. Returns a finding if failed."""
    query_fn = QUERY_REGISTRY.get(check.query)
    if query_fn is None:
        logger.warning("Unknown content query: %s (check %s)", check.query, check.id)
        return None

    check_args: dict[str, Any] = dict(check.args or {})
    target_files = _matching_files(ruleset_map, classified, rule.match)
    if not target_files:
        return None

    found = any(query_fn(ruleset_map, fp, **check_args).found for fp in target_files)
    passed = found if check.expect == "present" else not found
    if passed:
        return None

    message = check_args.get("message", "")
    if not message:
        message = f"Content check failed: {check.query} (expect={check.expect})"

    display_path = _relative_path(target_files[0] if target_files else primary_file)
    return LocalFinding(
        file=display_path,
        line=1,
        severity=rule.severity.value,
        rule=rule.id,
        message=message,
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
    required content. One finding per rule failure.
    """
    if classified is None:
        classified = []

    primary_file = ruleset_map.files[0].path if ruleset_map.files else ""
    findings: list[LocalFinding] = []

    for rule in rules.values():
        for check in rule.checks:
            if check.type != "content_query" or not check.query:
                continue
            finding = _evaluate_check(ruleset_map, check, rule, classified, primary_file)
            if finding is not None:
                findings.append(finding)

    return findings


def _relative_path(file_path: str) -> str:
    """Normalize file path for display. Uses merger's normalize_finding_path."""
    from reporails_cli.core.merger import normalize_finding_path

    return normalize_finding_path(file_path)
