"""Regex execution engine + SARIF output.

Executes compiled regex checks against target files and produces
SARIF-compatible output matching the downstream pipeline format.
"""
# pylint: disable=too-many-lines

from __future__ import annotations

import fnmatch
import logging
import re
from pathlib import Path, PurePosixPath
from typing import Any

from reporails_cli.bundled import get_capability_patterns_path
from reporails_cli.core.models import Rule
from reporails_cli.core.regex.compiler import (
    CombinedPattern,
    CompiledCheck,
    build_combined_patterns,
    compile_rules,
)

logger = logging.getLogger(__name__)


def _find_line_number(content: str, match: re.Match[str]) -> int:
    """Count newlines before match start position."""
    return content[: match.start()].count("\n") + 1


def _get_snippet(match: re.Match[str], max_len: int = 200) -> str:
    """Extract a snippet around the match for SARIF output."""
    text = match.group(0)
    return text[:max_len] + "..." if len(text) > max_len else text


def _file_matches_path_filter(file_path: str, path_includes: tuple[str, ...]) -> bool:
    """Check if a file path matches any of the path include patterns.

    Handles ``**`` as zero-or-more directory components (matching glob/OpenGrep
    semantics) via PurePosixPath.match(), with fnmatch fallback for simple patterns.
    """
    if not path_includes:
        return True
    filename = Path(file_path).name
    rel = file_path.lstrip("./")
    p = PurePosixPath(rel)
    for pattern in path_includes:
        if "{{" in pattern:
            continue
        # PurePosixPath.match handles ** as zero-or-more directories (Python 3.12+)
        if "**" in pattern:
            clean_pattern = pattern.lstrip("./")
            if p.match(clean_pattern):
                return True
            # Also check if ** should match zero directories
            if "**/" in clean_pattern:
                collapsed = clean_pattern.replace("**/", "")
                if fnmatch.fnmatch(rel, collapsed) or fnmatch.fnmatch(filename, collapsed):
                    return True
            continue
        if any(fnmatch.fnmatch(candidate, pattern) for candidate in (file_path, filename, rel)):
            return True
    return False


def _append_extra(seen: set[Path], targets: list[Path], extra_targets: list[Path] | None) -> None:
    """Append extra targets (deduped by resolved path)."""
    if not extra_targets:
        return
    for extra in extra_targets:
        resolved = extra.resolve()
        if resolved not in seen and resolved.exists():
            seen.add(resolved)
            targets.append(resolved)


def _resolve_scan_targets(
    target: Path,
    instruction_files: list[Path] | None,
    extra_targets: list[Path] | None,
) -> list[Path]:
    """Build scan targets from instruction files or directory scan."""
    if instruction_files:
        seen: set[Path] = set()
        targets: list[Path] = []
        for ifile in instruction_files:
            resolved = ifile.resolve()
            if resolved not in seen and resolved.exists():
                seen.add(resolved)
                targets.append(resolved)
        _append_extra(seen, targets, extra_targets)
        return targets

    scan_dir = target if target.is_dir() else target.parent
    targets = list(scan_dir.rglob("*.md"))
    seen = {t.resolve() for t in targets}
    _append_extra(seen, targets, extra_targets)
    return targets


def _is_text_file(file_path: Path) -> bool:
    """Quick check if a file is likely text (not binary)."""
    try:
        with open(file_path, "rb") as f:
            return b"\x00" not in f.read(8192)
    except OSError:
        return False


def _match_check(check: CompiledCheck, content: str) -> list[re.Match[str]]:
    """Execute a single compiled check against file content."""
    if check.either_patterns:
        return [m for pat in check.either_patterns if (m := pat.search(content))]

    matches = []
    for pat in check.patterns:
        m = pat.search(content)
        if not m:
            return []
        matches.append(m)

    for pat in check.negative_patterns:
        if pat.search(content):
            return []

    return matches


def _build_sarif(
    rule_results: list[dict[str, Any]],
    rule_definitions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build SARIF output dict matching downstream pipeline format."""
    return {
        "runs": [
            {
                "tool": {"driver": {"rules": rule_definitions}},
                "results": rule_results,
            }
        ],
    }


def _should_exclude(file_path: Path, scan_root: Path, exclude_dirs: list[str] | None) -> bool:
    """Check if file should be excluded based on directory exclusion list."""
    if not exclude_dirs:
        return False
    try:
        rel = file_path.relative_to(scan_root)
    except ValueError:
        return False
    return bool(set(exclude_dirs) & set(rel.parts))


def _partition_checks(
    checks: list[CompiledCheck],
) -> tuple[list[CompiledCheck], dict[str, list[CompiledCheck]]]:
    """Pre-partition checks into universal (no path filter) and path-filtered groups.

    Returns:
        (universal_checks, path_pattern_to_checks_map)
    """
    universal: list[CompiledCheck] = []
    by_pattern: dict[str, list[CompiledCheck]] = {}
    for check in checks:
        if not check.path_includes:
            universal.append(check)
        else:
            key = "|".join(check.path_includes)
            by_pattern.setdefault(key, []).append(check)
    return universal, by_pattern


def _get_applicable_checks(
    file_path: Path,
    scan_root: Path,
    universal: list[CompiledCheck],
    by_pattern: dict[str, list[CompiledCheck]],
) -> list[CompiledCheck]:
    """Get checks applicable to a file — universal + path-matched."""
    if not by_pattern:
        return universal

    try:
        rel_path = str(file_path.relative_to(scan_root))
    except ValueError:
        rel_path = file_path.name

    applicable = list(universal)
    for checks in by_pattern.values():
        # All checks in this group share the same path_includes
        if _file_matches_path_filter(rel_path, checks[0].path_includes):
            applicable.extend(checks)
    return applicable


def _emit_results(
    check: CompiledCheck,
    matches: list[re.Match[str]],
    file_uri: str,
    content: str,
    results: list[dict[str, Any]],
    rule_defs: dict[str, dict[str, Any]],
) -> None:
    """Append SARIF results for matched check."""
    if check.id not in rule_defs:
        rule_defs[check.id] = {
            "id": check.id,
            "defaultConfiguration": {"level": check.severity},
        }

    for match in matches:
        line = _find_line_number(content, match)
        snippet = _get_snippet(match)
        results.append(
            {
                "ruleId": check.id,
                "message": {"text": check.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_uri},
                            "region": {
                                "startLine": line,
                                "snippet": {"text": snippet},
                            },
                        }
                    }
                ],
            }
        )


def _scan_combined(
    content: str,
    file_uri: str,
    combined_patterns: list[CombinedPattern],
    results: list[dict[str, Any]],
    rule_defs: dict[str, dict[str, Any]],
) -> None:
    """Scan content using combined alternation patterns for batch matching.

    Emits at most one match per check per file, matching the behavior of
    re.search() in the individual check path.
    """
    for combined in combined_patterns:
        # Track which checks already matched (first match per check)
        matched_checks: set[str] = set()
        for m in combined.regex.finditer(content):
            group_name = m.lastgroup
            if group_name and group_name not in matched_checks:
                check = combined.group_to_check[group_name]
                _emit_results(check, [m], file_uri, content, results, rule_defs)
                matched_checks.add(group_name)
                # Early exit when all checks have matched
                if len(matched_checks) == len(combined.group_to_check):
                    break


def _scan_file(
    file_path: Path,
    scan_root: Path,
    checks: list[CompiledCheck],
    results: list[dict[str, Any]],
    rule_defs: dict[str, dict[str, Any]],
    *,
    first_match_only: bool = False,
    combined_patterns: list[CombinedPattern] | None = None,
) -> None:
    """Scan a single file against compiled checks, appending to results."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return

    try:
        file_uri = str(file_path.relative_to(scan_root))
    except ValueError:
        file_uri = str(file_path)

    # Use combined patterns for simple checks
    if combined_patterns:
        _scan_combined(content, file_uri, combined_patterns, results, rule_defs)

    # Run remaining complex checks individually
    for check in checks:
        matches = _match_check(check, content)
        if not matches:
            continue

        if first_match_only:
            _emit_results(check, matches[:1], file_uri, content, results, rule_defs)
        else:
            _emit_results(check, matches, file_uri, content, results, rule_defs)


def run_validation(  # pylint: disable=too-many-locals
    yml_paths: list[Path],
    target: Path,
    template_context: dict[str, str | list[str]] | None = None,
    extra_targets: list[Path] | None = None,
    instruction_files: list[Path] | None = None,
    exclude_dirs: list[str] | None = None,
) -> dict[str, Any]:
    """Execute regex validation with specified rule configs, returns SARIF-shaped dict.

    Main entry point for regex-based rule validation.

    Args:
        yml_paths: Paths to YAML rule files
        target: Directory or file to scan
        template_context: Template variables for {{placeholder}} resolution
        extra_targets: Additional file paths to scan
        instruction_files: Explicit list of files to scan
        exclude_dirs: Directory names to exclude from scanning

    Returns:
        SARIF-compatible dict with runs[].results[]
    """
    valid_paths = [p for p in yml_paths if p and p.exists()]
    if not valid_paths:
        return {"runs": []}

    ruleset = compile_rules(valid_paths, template_context)
    if not ruleset.checks:
        return {"runs": []}

    if ruleset.skipped:
        logger.warning("Skipped rules with unsupported operators: %s", ", ".join(ruleset.skipped))

    scan_targets = _resolve_scan_targets(target, instruction_files, extra_targets)
    if not scan_targets:
        return {"runs": []}

    scan_root = target if target.is_dir() else target.parent
    results: list[dict[str, Any]] = []
    rule_defs: dict[str, dict[str, Any]] = {}

    # Partition checks into universal (no path filter) and path-filtered groups
    universal, by_pattern = _partition_checks(ruleset.checks)

    # Build combined patterns for universal checks only — path-filtered checks
    # run individually (combined alternation is slower for complex/flagged patterns)
    combined, complex_universal = build_combined_patterns(universal)

    for file_path in scan_targets:
        if not file_path.is_file():
            continue
        if _should_exclude(file_path, scan_root, exclude_dirs):
            continue

        # Get path-filtered checks applicable to this file
        path_checks = _get_applicable_checks(file_path, scan_root, [], by_pattern)
        individual = complex_universal + path_checks

        # Skip files with no applicable checks
        if not individual and not combined:
            continue

        if not _is_text_file(file_path):
            continue
        _scan_file(
            file_path,
            scan_root,
            individual,
            results,
            rule_defs,
            combined_patterns=combined,
        )

    return _build_sarif(results, list(rule_defs.values()))


def run_capability_detection(  # pylint: disable=too-many-locals
    target: Path,
    extra_targets: list[Path] | None = None,
    instruction_files: list[Path] | None = None,
) -> dict[str, Any]:
    """Run capability detection using bundled patterns.

    Only needs boolean presence per check, so uses first_match_only=True
    for faster scanning.

    Args:
        target: Directory to scan
        extra_targets: Additional file paths to scan
        instruction_files: Explicit list of files to scan

    Returns:
        SARIF-compatible dict
    """
    patterns_path = get_capability_patterns_path()
    if not patterns_path.exists():
        logger.warning("Capability patterns not found: %s", patterns_path)
        return {"runs": []}

    # Use first_match_only for capability detection — only need presence, not all matches
    valid_paths = [patterns_path]
    ruleset = compile_rules(valid_paths)
    if not ruleset.checks:
        return {"runs": []}

    scan_targets = _resolve_scan_targets(target, instruction_files, extra_targets)
    if not scan_targets:
        return {"runs": []}

    scan_root = target if target.is_dir() else target.parent
    results: list[dict[str, Any]] = []
    rule_defs: dict[str, dict[str, Any]] = {}
    universal, by_pattern = _partition_checks(ruleset.checks)
    combined, complex_universal = build_combined_patterns(universal)

    for file_path in scan_targets:
        if not file_path.is_file():
            continue

        path_checks = _get_applicable_checks(file_path, scan_root, [], by_pattern)
        individual = complex_universal + path_checks

        if not individual and not combined:
            continue
        if not _is_text_file(file_path):
            continue
        _scan_file(
            file_path,
            scan_root,
            individual,
            results,
            rule_defs,
            first_match_only=True,
            combined_patterns=combined,
        )

    return _build_sarif(results, list(rule_defs.values()))


def checks_per_file(
    yml_paths: list[Path],
    scan_root: Path,
    template_context: dict[str, str | list[str]] | None,
    instruction_files: list[Path] | None,
) -> dict[str, list[str]]:
    """List compiled regex check IDs applicable to each file (path filter logic only, no matching).

    Args:
        yml_paths: Rule YAML paths
        scan_root: Project root
        template_context: Template variables
        instruction_files: Files to count against

    Returns:
        Dict of relative file path -> list of check IDs
    """
    ruleset = compile_rules([p for p in yml_paths if p and p.exists()], template_context)
    if not ruleset.checks:
        return {}

    universal, by_pattern = _partition_checks(ruleset.checks)
    combined, complex_universal = build_combined_patterns(universal)
    base_ids = [c.id for c in complex_universal]
    for cp in combined:
        base_ids.extend(c.id for c in cp.group_to_check.values())

    result: dict[str, list[str]] = {}
    for file_path in instruction_files or []:
        if not file_path.is_file():
            continue
        try:
            rel = str(file_path.relative_to(scan_root))
        except ValueError:
            rel = str(file_path)
        path_ids = [c.id for c in _get_applicable_checks(file_path, scan_root, [], by_pattern)]
        result[rel] = base_ids + path_ids

    return result


def get_rule_yml_paths(rules: dict[str, Rule]) -> list[Path]:
    """Get list of .yml paths for rules that have them and exist.

    Args:
        rules: Dict of rules

    Returns:
        List of paths to existing .yml files
    """
    return [r.yml_path for r in rules.values() if r.yml_path is not None and r.yml_path.exists()]
