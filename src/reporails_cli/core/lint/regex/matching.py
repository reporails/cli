"""Pattern matching of one compiled check against one file's text, bounded by a search timeout."""

from __future__ import annotations

import logging

import regex as re

from reporails_cli.core.lint.regex.compiler import CompiledCheck
from reporails_cli.core.lint.regex.not_evaluated import PatternTimeoutError
from reporails_cli.core.platform.utils.utils import strip_frontmatter

logger = logging.getLogger(__name__)


def find_line_number(content: str, match: re.Match[str]) -> int:
    """The 1-based line of `content` where `match` starts."""
    return content[: match.start()].count("\n") + 1


REGEX_TIMEOUT_S = 0.5


def safe_search(pat: re.Pattern[str], content: str) -> re.Match[str] | None:
    """Run pat.search with the regex library's native timeout; raises `PatternTimeoutError` when it runs out."""
    try:
        return pat.search(content, timeout=REGEX_TIMEOUT_S)
    except TimeoutError as exc:
        logger.warning("Regex search timed out after %.1fs: %s", REGEX_TIMEOUT_S, pat.pattern[:80])
        raise PatternTimeoutError(pat.pattern[:80]) from exc


def safe_finditer(pat: re.Pattern[str], content: str) -> list[re.Match[str]]:
    """Run pat.finditer with the regex library's native timeout; raises `PatternTimeoutError` when it runs out."""
    try:
        return list(pat.finditer(content, timeout=REGEX_TIMEOUT_S))
    except TimeoutError as exc:
        logger.warning("Regex finditer timed out after %.1fs: %s", REGEX_TIMEOUT_S, pat.pattern[:80])
        raise PatternTimeoutError(pat.pattern[:80]) from exc


def _any_of_matches(patterns: tuple[re.Pattern[str], ...], content: str) -> list[re.Match[str]]:
    """The first match of each pattern that has one; a pattern that runs out of time is skipped.

    Raises `PatternTimeoutError` only when nothing matched and some pattern ran out of time.
    """
    matches: list[re.Match[str]] = []
    timed_out: PatternTimeoutError | None = None
    for pat in patterns:
        try:
            m = safe_search(pat, content)
        except PatternTimeoutError as exc:
            timed_out = exc
            continue
        if m:
            matches.append(m)
    if not matches and timed_out is not None:
        raise timed_out
    return matches


def match_check(
    check: CompiledCheck,
    content: str,
    body_content: str | None = None,
) -> list[re.Match[str]]:
    """Execute a single compiled check against file content.

    Every `pat.search` runs through `safe_search`, so the `regex` library's
    native `timeout=` bounds a pathological pattern rather than letting it hang
    the scan; the 1 MB file-size cap is the second bound.
    """
    if check.body_only:
        content = body_content if body_content is not None else strip_frontmatter(content, keep_lines=True)
    if check.either_patterns:
        return _any_of_matches(check.either_patterns, content)

    matches = []
    for pat in check.patterns:
        m = safe_search(pat, content)
        if not m:
            return []
        matches.append(m)

    for pat in check.negative_patterns:
        if safe_search(pat, content):
            return []

    return matches


def every_match_lines(
    check: CompiledCheck,
    content: str,
    body_content: str | None = None,
) -> list[re.Match[str]]:
    """Every matching line of a check that forbids something: its first match on each line.

    A check made of several patterns that must all match reports the lines of its last pattern
    (the earlier ones only gate the check, e.g. "this is a hooks block"), so one forbidden thing
    is one finding, not one per pattern; a single pattern, or an either-set, reports each line it matches.
    """
    first = match_check(check, content, body_content)
    if not first:
        return first
    if check.body_only:
        content = body_content if body_content is not None else strip_frontmatter(content, keep_lines=True)
    try:
        found = sorted(
            (m for pat in (check.either_patterns or check.patterns[-1:]) for m in safe_finditer(pat, content)),
            key=lambda m: m.start(),
        )
    except PatternTimeoutError:
        found = []
    one_per_line: dict[int, re.Match[str]] = {}
    for m in found:
        one_per_line.setdefault(find_line_number(content, m), m)
    return list(one_per_line.values()) or (first if check.either_patterns else first[-1:])
