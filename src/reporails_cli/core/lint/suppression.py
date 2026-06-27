"""Inline per-line finding suppression.

An author marks a single reviewed finding as intentional with a rule-named
inline directive on the offending line; the rule stays armed on every other
line. Filtering runs after merge, before display and before strict gating.

Directive form (inline HTML comment, invisible when the file renders):

    Some instruction here.  <!-- ails-disable-line CORE:C:0049 -->

The directive must name at least one rule (space- or comma-separated for
several); a bare directive with no rule names nothing.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any

# Canonical form is an inline HTML comment, invisible when the file renders.
_DIRECTIVE_RE = re.compile(r"<!--\s*ails-disable-line\b(?P<rules>[^>]*?)-->")
_RULE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")

# (file, line) -> set of rule names the author chose to silence on that line.
SuppressionIndex = dict[tuple[str, int], set[str]]


def _rule_tokens(captured: str) -> set[str]:
    """Pull valid rule names out of a directive's body, dropping separators."""
    return {tok for tok in re.split(r"[,\s]+", captured.strip()) if _RULE_TOKEN_RE.match(tok)}


def parse_directives(text: str) -> dict[int, set[str]]:
    """Map 1-based line number to the set of rule names suppressed on that line."""
    out: dict[int, set[str]] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in _DIRECTIVE_RE.finditer(line):
            rules = _rule_tokens(match.group("rules"))
            if rules:
                out.setdefault(lineno, set()).update(rules)
    return out


def strip_directives(content: str) -> str:
    """Remove suppression-directive comments so they never reach classification.

    Replaces each directive comment with an equal run of spaces, preserving
    every newline and column offset so atom line numbers stay exact.
    """
    return _DIRECTIVE_RE.sub(lambda m: " " * (m.end() - m.start()), content)


def build_index(
    finding_files: Iterable[str],
    project_root: Path | None,
) -> SuppressionIndex:
    """Scan each finding-bearing file for directives and key them by (file, line).

    Directives are parsed from the import-EXPANDED content, the same coordinate
    space the classifier assigns finding line numbers in (`strip_directives(
    expand_imports(...))`). Parsing the raw file instead would diverge whenever an
    `@import` precedes a directive, so the suppression would silently miss.
    """
    from reporails_cli.core.mapper.imports import expand_imports

    index: SuppressionIndex = {}
    for rel in set(finding_files):
        path = _resolve(rel, project_root)
        if path is None:
            continue
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            text = expand_imports(raw, path)
        except (OSError, UnicodeDecodeError, RecursionError):
            text = raw
        for lineno, rules in parse_directives(text).items():
            index[(rel, lineno)] = rules
    return index


def suppressed_lines(
    finding_files: Iterable[str],
    project_root: Path | None,
) -> dict[str, set[int]]:
    """Per-file set of lines carrying any suppression directive (for the heal write path).

    Heal must not mechanically rewrite a line the author explicitly annotated as
    reviewed with an `ails-disable-line` directive; this surfaces those lines keyed
    by the same expanded coordinate space the atoms use.
    """
    out: dict[str, set[int]] = {}
    for rel, lineno in build_index(finding_files, project_root):
        out.setdefault(rel, set()).add(lineno)
    return out


def is_suppressed(
    finding: Any,
    index: SuppressionIndex,
    alias_fn: Callable[[str], set[str]] | None = None,
) -> bool:
    """True when a directive on the finding's line names the finding's rule."""
    named = index.get((finding.file, finding.line))
    if not named:
        return False
    aliases = alias_fn(finding.rule) if alias_fn else {finding.rule}
    return bool(named & aliases)


def apply_suppressions(
    result: Any,
    project_root: Path | None = None,
    alias_fn: Callable[[str], set[str]] | None = None,
) -> Any:
    """Return `result` with directive-suppressed findings removed and stats rebuilt."""
    if not result.findings:
        return result
    index = build_index((f.file for f in result.findings), project_root)
    if not index:
        return result
    kept = tuple(f for f in result.findings if not is_suppressed(f, index, alias_fn))
    if len(kept) == len(result.findings):
        return result
    return replace(result, findings=kept, stats=_rebuild_stats(result.stats, kept))


def _rebuild_stats(stats: Any, findings: tuple[Any, ...]) -> Any:
    """Recompute the severity counters over the kept findings, source counts preserved."""
    return replace(
        stats,
        total_findings=len(findings),
        errors=sum(1 for f in findings if f.severity == "error"),
        warnings=sum(1 for f in findings if f.severity == "warning"),
        infos=sum(1 for f in findings if f.severity == "info"),
    )


def _resolve(rel: str, project_root: Path | None) -> Path | None:
    """Reconstruct an absolute path from a normalized finding path."""
    if rel.startswith("~/"):
        return Path.home() / rel[2:]
    p = Path(rel)
    if p.is_absolute():
        return p
    if project_root is None:
        return p
    return project_root / p
