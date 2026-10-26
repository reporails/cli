"""Expect findings — turn the matches of a scan into findings for what a check expects present or absent."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.lint.regex.compiler import CompiledCheck
from reporails_cli.core.lint.regex.not_evaluated import record_not_evaluated, rule_id_of
from reporails_cli.core.platform.contract.glob_pattern import glob_matches
from reporails_cli.core.platform.dto.models import LocalFinding


@dataclass(frozen=True)
class _ScanOutcome:
    """What a scan found, for the checks to be judged against (see `emit_expect_findings`)."""

    matched_pairs: set[tuple[str, str]]
    match_details: dict[tuple[str, str], list[tuple[int, str, str]]]
    scanned_files: list[str]
    scan_root: Path | None = None
    fix_by_rule: dict[str, str] = field(default_factory=dict)
    skill_entries: set[Path] | None = None
    not_evaluated: set[tuple[str, str]] = field(default_factory=set)


def emit_expect_findings(
    checks: list[CompiledCheck],
    matched_pairs: set[tuple[str, str]],
    match_details: dict[tuple[str, str], list[tuple[int, str, str]]],
    scanned_files: list[str],
    *,
    scan_root: Path | None = None,
    fix_by_rule: dict[str, str] | None = None,
    skill_entries: set[Path] | None = None,
    not_evaluated: set[tuple[str, str]] | None = None,
) -> list[LocalFinding]:
    """Convert expect/match results to LocalFinding list.

    `not_evaluated` holds the `(check id, file)` pairs whose search ran out of time; such a
    check says nothing about that file, whether it expects the pattern present or absent.

    A check with `entry_only` reports on a skill's entry file alone when `skill_entries` (the
    resolved entry files of the run) is given; without it the check applies to every file it names.

    A check that declares `paths.include` only reports on the files those filters name: a
    file outside them is neither failing nor passing it.

    When a check declares `min_lines`, files below that line count are
    skipped — neither marked as failing nor as passing. Used by rules
    like `CORE:S:0013 scope-fields-in-frontmatter` where the scope
    declaration is boilerplate for tiny files.

    `fix_by_rule` maps full rule ids (e.g. `CORE:S:0013`) to the
    canonical fix text declared in `rule.md` frontmatter. Propagates to
    `LocalFinding.fix` so MCP / JSON consumers can render the suggested
    edit. Empty when the rule has no declared fix.
    """
    outcome = _ScanOutcome(
        matched_pairs, match_details, scanned_files, scan_root, fix_by_rule or {}, skill_entries, not_evaluated or set()
    )
    findings: list[LocalFinding] = []
    for check in checks:
        findings.extend(_check_findings(check, outcome))
    return findings


def _check_findings(check: CompiledCheck, outcome: _ScanOutcome) -> list[LocalFinding]:
    """The findings of one check: every forbidden match, or every scanned file lacking the expected pattern."""
    rule_id = rule_id_of(check.id)
    fix_text = outcome.fix_by_rule.get(rule_id, "")
    applicable = [f for f in outcome.scanned_files if _entry_ok(check, f, outcome.scan_root, outcome.skill_entries)]
    for f in applicable:
        if (check.id, f) in outcome.not_evaluated and _applies_to(check, f, outcome.scan_root):
            record_not_evaluated(rule_id, f)
    scanned = [f for f in applicable if (check.id, f) not in outcome.not_evaluated]
    if check.every_match:
        # A match can sit in a file the scan did not list: the text an `@path` import splices in.
        imported = sorted(
            fp for cid, fp in outcome.matched_pairs if cid == check.id and fp not in outcome.scanned_files
        )
        return _forbidden_findings(check, rule_id, fix_text, [*scanned, *imported], outcome)
    return _missing_findings(check, rule_id, fix_text, scanned, outcome)


def _forbidden_findings(
    check: CompiledCheck, rule_id: str, fix_text: str, files: list[str], outcome: _ScanOutcome
) -> list[LocalFinding]:
    """One finding per matched line of a check that forbids something."""
    return [
        LocalFinding(
            file=file_path,
            line=line,
            severity=check.severity,
            rule=rule_id,
            message=match_msg or check.message,
            fix=fix_text,
            source="m_probe",
            check_id=check.id,
            signature=snippet,
        )
        for file_path in files
        for line, match_msg, snippet in outcome.match_details.get((check.id, file_path), ())
    ]


def _missing_findings(
    check: CompiledCheck, rule_id: str, fix_text: str, files: list[str], outcome: _ScanOutcome
) -> list[LocalFinding]:
    """One finding per file the check considers that lacks the pattern it expects."""
    return [
        LocalFinding(
            file=file_path,
            line=1,
            severity=check.severity,
            rule=rule_id,
            message=check.message,
            fix=fix_text,
            source="m_probe",
            check_id=check.id,
        )
        for file_path in files
        if (check.id, file_path) not in outcome.matched_pairs
        and file_matches_path_filter(file_path, check.path_includes)
        and not file_below_min_lines(file_path, check.min_lines, outcome.scan_root)
    ]


def file_matches_path_filter(file_path: str, path_includes: tuple[str, ...]) -> bool:
    """Check if a file path matches any of the path include patterns (a templated one never does)."""
    if not path_includes:
        return True
    return any("{{" not in pattern and glob_matches(file_path, pattern) for pattern in path_includes)


def _applies_to(check: CompiledCheck, rel_path: str, scan_root: Path | None) -> bool:
    """Whether `check` considers `rel_path`: the file passes its path filter and is not below its `min_lines`."""
    return file_matches_path_filter(rel_path, check.path_includes) and not file_below_min_lines(
        rel_path, check.min_lines, scan_root
    )


def _entry_ok(check: CompiledCheck, rel_path: str, scan_root: Path | None, entries: set[Path] | None) -> bool:
    """Whether `check` applies to `rel_path`: an `entry_only` check skips a file that is no skill's entry file."""
    if not check.entry_only or entries is None:
        return True
    return safe_resolve((scan_root or Path()) / rel_path) in entries


def file_below_min_lines(rel_path: str, min_lines: int, scan_root: Path | None) -> bool:
    """Return True when `rel_path` exists under `scan_root` with fewer than `min_lines` lines.

    Files we cannot read are treated as not-below (the deterministic check
    still fires, matching pre-`min_lines` behaviour).
    """
    if min_lines <= 0 or scan_root is None:
        return False
    full = scan_root / rel_path
    try:
        return len(full.read_text(encoding="utf-8-sig", errors="replace").splitlines()) < min_lines
    except OSError:
        return False


def apply_min_lines_overrides(checks: list[CompiledCheck], overrides: dict[str, int]) -> list[CompiledCheck]:
    """Merge `rule_thresholds[rule_id].min_lines` over per-check defaults.

    The override key is the rule id (e.g. `CORE:S:0013`); the check
    id (e.g. `CORE.S.0013.pattern_check`) extends it.
    """
    out: list[CompiledCheck] = []
    for check in checks:
        rule_id = rule_id_of(check.id)
        out.append(replace(check, min_lines=int(overrides[rule_id])) if rule_id in overrides else check)
    return out
