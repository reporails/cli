"""Regex execution engine + SARIF output."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import regex as re

from reporails_cli.core.discovery.exclusions import load_project_exclude_dirs
from reporails_cli.core.discovery.walk import safe_resolve, walk_files, walk_markdown
from reporails_cli.core.lint.regex import matching
from reporails_cli.core.lint.regex.compiler import (
    CombinedPattern,
    CompiledCheck,
    CompiledRuleSet,
    compile_rules,
)
from reporails_cli.core.lint.regex.expect import (
    apply_min_lines_overrides,
    emit_expect_findings,
    file_matches_path_filter,
)
from reporails_cli.core.lint.regex.not_evaluated import PatternTimeoutError
from reporails_cli.core.mapper.imports import expand_imports_with_origins
from reporails_cli.core.platform.dto.models import LocalFinding

logger = logging.getLogger(__name__)


def _get_snippet(match: re.Match[str], max_len: int = 200) -> str:
    text: str = match.group(0)
    return text[:max_len] + "..." if len(text) > max_len else text


def _append_extra(seen: set[Path], targets: list[Path], extra_targets: list[Path] | None) -> None:
    """Append extra targets (deduped by resolved path)."""
    if not extra_targets:
        return
    for extra in extra_targets:
        resolved = safe_resolve(extra)
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
            resolved = safe_resolve(ifile)
            if resolved not in seen and resolved.exists():
                seen.add(resolved)
                targets.append(ifile)
        _append_extra(seen, targets, extra_targets)
        return targets

    scan_dir = target if target.is_dir() else target.parent
    excluded = load_project_exclude_dirs(scan_dir)
    targets = list(walk_markdown(scan_dir, excluded))
    if not targets:
        targets = list(walk_files(scan_dir, excluded, _is_text_file))
    seen = {safe_resolve(t) for t in targets}
    _append_extra(seen, targets, extra_targets)
    return targets


def _is_text_file(file_path: Path) -> bool:
    """Quick check if a file is likely text (not binary)."""
    try:
        with open(file_path, "rb") as f:
            return b"\x00" not in f.read(8192)
    except OSError:
        return False


def _build_sarif(
    rule_results: list[dict[str, Any]],
    rule_definitions: list[dict[str, Any]],
    unfinished: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Build SARIF output dict matching downstream pipeline format.

    `unfinished` lists the `(check id, file uri)` pairs whose search ran out of time; they
    ride under `notEvaluated`.
    """
    return {
        "notEvaluated": [{"checkId": cid, "uri": uri} for cid, uri in dict.fromkeys(unfinished or ())],
        "runs": [
            {
                "tool": {"driver": {"rules": rule_definitions}},
                "results": rule_results,
            }
        ],
    }


def _partition_checks(
    checks: list[CompiledCheck],
) -> tuple[list[CompiledCheck], dict[str, list[CompiledCheck]]]:
    """Pre-partition checks into universal (no path filter) and path-filtered groups."""
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
        rel_path = file_path.relative_to(scan_root).as_posix()
    except ValueError:
        rel_path = file_path.name

    applicable = list(universal)
    for checks in by_pattern.values():
        if file_matches_path_filter(rel_path, checks[0].path_includes):
            applicable.extend(checks)
    return applicable


def _relative_uri(path: Path, scan_root: Path) -> str:
    """`path` relative to the scan root as written in a result, or as it is when outside it."""
    for root in (scan_root, safe_resolve(scan_root)):
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            continue
    return path.as_posix()


def _emit_results(
    check: CompiledCheck,
    matches: list[re.Match[str]],
    file_uri: str,
    content: str,
    *,
    results: list[dict[str, Any]],
    rule_defs: dict[str, dict[str, Any]],
    imports: tuple[list[int], list[tuple[Path, int] | None], Path] | None = None,
) -> None:
    """Append SARIF results for matched check.

    `imports` is the line map and line origins of import-expanded `content` plus the scan root: a match
    is then reported on the file and line where its text is written.
    """
    if check.id not in rule_defs:
        rule_defs[check.id] = {
            "id": check.id,
            "defaultConfiguration": {"level": check.severity},
        }

    for match in matches:
        line = matching.find_line_number(content, match)
        uri = file_uri
        if imports:
            line_map, origins, scan_root = imports
            origin = origins[line - 1]
            if origin is None:
                line = line_map[line - 1]
            else:
                uri, line = _relative_uri(origin[0], scan_root), origin[1]
        snippet = _get_snippet(match)
        results.append(
            {
                "ruleId": check.id,
                "message": {"text": check.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {
                                "startLine": line,
                                "snippet": {"text": snippet},
                            },
                        }
                    }
                ],
            }
        )


def _retry_shadowed(
    group_to_check: dict[str, CompiledCheck],
    matched_checks: set[str],
    content: str,
    file_uri: str,
    *,
    results: list[dict[str, Any]],
    rule_defs: dict[str, dict[str, Any]],
) -> None:
    """Retry shadowed checks. No per-pattern timeout — see matching.match_check note."""
    for group_name, check in group_to_check.items():
        if group_name in matched_checks:
            continue
        if check.patterns:
            m = check.patterns[0].search(content)
            if m:
                _emit_results(check, [m], file_uri, content, results=results, rule_defs=rule_defs)
        elif check.either_patterns:
            for pat in check.either_patterns:
                m = pat.search(content)
                if m:
                    _emit_results(check, [m], file_uri, content, results=results, rule_defs=rule_defs)
                    break


def _scan_combined(
    content: str,
    file_uri: str,
    combined_patterns: list[CombinedPattern],
    *,
    results: list[dict[str, Any]],
    rule_defs: dict[str, dict[str, Any]],
    unfinished: list[tuple[str, str]],
) -> None:
    """Scan content using combined alternation patterns for batch matching.

    A combined pattern that runs out of time leaves every check it carries unevaluated for this file.
    """
    for combined in combined_patterns:
        matched_checks: set[str] = set()
        try:
            found = matching.safe_finditer(combined.regex, content)
        except PatternTimeoutError:
            unfinished.extend((c.id, file_uri) for c in combined.group_to_check.values())
            continue
        for m in found:
            group_name = m.lastgroup
            if group_name and group_name not in matched_checks:
                check = combined.group_to_check[group_name]
                _emit_results(check, [m], file_uri, content, results=results, rule_defs=rule_defs)
                matched_checks.add(group_name)
                if len(matched_checks) == len(combined.group_to_check):
                    break

        if len(matched_checks) < len(combined.group_to_check):
            _retry_shadowed(
                combined.group_to_check, matched_checks, content, file_uri, results=results, rule_defs=rule_defs
            )


_MAX_FILE_SIZE = 1_048_576  # 1 MB


def _check_hits(
    check: CompiledCheck,
    content: str,
    expanded: tuple[str, list[int], list[tuple[Path, int] | None]] | None,
    scan_root: Path,
) -> tuple[list[re.Match[str]], str, tuple[list[int], list[tuple[Path, int] | None], Path] | None]:
    """A check's matches, the text they were found in, and the import line mapping to report them against.

    A check that follows imports reads the import-expanded text; any other reads the file as written.
    """
    imports = None
    if check.follow_imports and expanded:
        content, imports = expanded[0], (expanded[1], expanded[2], scan_root)
    match_fn = matching.every_match_lines if check.every_match else matching.match_check
    return match_fn(check, content), content, imports


def _scan_file(
    file_path: Path,
    scan_root: Path,
    checks: list[CompiledCheck],
    results: list[dict[str, Any]],
    rule_defs: dict[str, dict[str, Any]],
    *,
    first_match_only: bool = False,
    combined_patterns: list[CombinedPattern] | None = None,
    unfinished: list[tuple[str, str]] | None = None,
) -> None:
    """Scan a single file against compiled checks, appending to results.

    A check whose search runs out of time yields no matches and is added to `unfinished`
    as `(check id, file uri)`.
    """
    unfinished = [] if unfinished is None else unfinished
    try:
        if file_path.stat().st_size > _MAX_FILE_SIZE:
            logger.debug("Skipping oversized file: %s", file_path)
            return
        content = file_path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return

    try:
        file_uri = file_path.relative_to(scan_root).as_posix()
    except ValueError:
        file_uri = file_path.as_posix()

    if combined_patterns:
        _scan_combined(
            content, file_uri, combined_patterns, results=results, rule_defs=rule_defs, unfinished=unfinished
        )

    expanded = expand_imports_with_origins(content, file_path) if any(c.follow_imports for c in checks) else None
    for check in checks:
        try:
            matches, text, imports = _check_hits(check, content, expanded, scan_root)
        except PatternTimeoutError:
            unfinished.append((check.id, file_uri))
            continue
        if matches:
            _emit_results(
                check,
                matches[:1] if first_match_only else matches,
                file_uri,
                text,
                results=results,
                rule_defs=rule_defs,
                imports=imports,
            )


def _scan_all_targets(
    scan_targets: list[Path],
    scan_root: Path,
    universal: list[CompiledCheck],
    by_pattern: dict[str, list[CompiledCheck]],
) -> dict[str, Any]:
    """Scan all targets and return SARIF-shaped dict."""
    results: list[dict[str, Any]] = []
    rule_defs: dict[str, dict[str, Any]] = {}
    unfinished: list[tuple[str, str]] = []
    for file_path in scan_targets:
        if not file_path.is_file():
            continue
        individual = universal + _get_applicable_checks(file_path, scan_root, [], by_pattern)
        if not individual or not _is_text_file(file_path):
            continue
        _scan_file(file_path, scan_root, individual, results, rule_defs, unfinished=unfinished)
    return _build_sarif(results, list(rule_defs.values()), unfinished)


def _compile_ruleset(yml_paths: list[Path], body_only_paths: set[Path] | None) -> CompiledRuleSet:
    """Compile the rule files that exist, warning about rules with unsupported operators."""
    valid_paths = [p for p in yml_paths if p and p.exists()]
    if not valid_paths:
        return CompiledRuleSet()
    ruleset = compile_rules(valid_paths, body_only_paths=body_only_paths)
    if ruleset.skipped:
        logger.warning("Skipped rules with unsupported operators: %s", ", ".join(ruleset.skipped))
    return ruleset


def _scan_ruleset(
    ruleset: CompiledRuleSet,
    target: Path,
    extra_targets: list[Path] | None = None,
    instruction_files: list[Path] | None = None,
) -> dict[str, Any]:
    """Run a compiled ruleset over the scan targets, returns SARIF-shaped dict."""
    if not ruleset.checks:
        return {"runs": []}
    scan_targets = _resolve_scan_targets(target, instruction_files, extra_targets)
    if not scan_targets:
        return {"runs": []}
    scan_root = target if target.is_dir() else target.parent
    universal, by_pattern = _partition_checks(ruleset.checks)
    return _scan_all_targets(scan_targets, scan_root, universal, by_pattern)


def run_validation(
    yml_paths: list[Path],
    target: Path,
    extra_targets: list[Path] | None = None,
    instruction_files: list[Path] | None = None,
    body_only_paths: set[Path] | None = None,
) -> dict[str, Any]:
    """Execute regex validation with specified rule configs, returns SARIF-shaped dict."""
    ruleset = _compile_ruleset(yml_paths, body_only_paths)
    return _scan_ruleset(ruleset, target, extra_targets, instruction_files)


def _collect_sarif_matches(
    sarif: dict[str, Any],
) -> tuple[set[tuple[str, str]], dict[tuple[str, str], list[tuple[int, str, str]]]]:
    """Extract matched (check_id, file) pairs and details from SARIF output.

    Each detail carries a matched line, its message, and the matched text
    (SARIF ``region.snippet.text``). The matched text lets the merge layer
    recognize when two rules with the same pattern flagged one secret, so it
    reports once instead of twice. A pair holds one detail per matched line.
    """
    pairs: set[tuple[str, str]] = set()
    details: dict[tuple[str, str], list[tuple[int, str, str]]] = {}
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            cid = result.get("ruleId", "")
            msg = result.get("message", {}).get("text", "")
            fp, ln, snippet = "", 0, ""
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                fp = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                ln = region.get("startLine", 0)
                snippet = region.get("snippet", {}).get("text", "")
                break
            pairs.add((cid, fp))
            entry = (ln, msg, snippet)
            if entry not in details.setdefault((cid, fp), []):
                details[(cid, fp)].append(entry)
    return pairs, details


def _collect_not_evaluated(sarif: dict[str, Any]) -> set[tuple[str, str]]:
    """The `(check id, file)` pairs whose search ran out of time, from SARIF output."""
    return {(e["checkId"], e["uri"]) for e in sarif.get("notEvaluated", ())}


def _resolve_scanned_files(
    target: Path,
    instruction_files: list[Path] | None,
) -> list[str]:
    """Build list of relative file paths that were scanned."""
    scan_root = target if target.is_dir() else target.parent
    scanned: list[str] = []
    for fp in _resolve_scan_targets(target, instruction_files, None):
        if not fp.is_file():
            continue
        try:
            scanned.append(fp.relative_to(scan_root).as_posix())
        except ValueError:
            scanned.append(fp.as_posix())
    return scanned


def run_checks(
    yml_paths: list[Path],
    target: Path,
    *,
    instruction_files: list[Path] | None = None,
    min_lines_overrides: dict[str, int] | None = None,
    fix_by_rule: dict[str, str] | None = None,
    skill_entries: set[Path] | None = None,
) -> list[LocalFinding]:
    """Execute regex validation and return LocalFinding list.

    `skill_entries` holds the resolved skill entry files of the run (None when it records no
    skills); an `entry_only` check reports on those alone.

    `min_lines_overrides` maps full rule IDs (e.g. `CORE:S:0013`) to
    integer minimum line counts; values override defaults declared in the
    rule's `checks.yml`. Populated by callers from `.ails/config.yml`
    `rule_thresholds`.

    `fix_by_rule` maps full rule IDs to the canonical fix text declared
    in `rule.md` frontmatter. Populated by callers from the rule
    registry; propagates to `LocalFinding.fix` so MCP / JSON consumers
    can render the per-finding suggested edit.
    """
    ruleset = _compile_ruleset(yml_paths, None)
    checks = apply_min_lines_overrides(ruleset.checks, min_lines_overrides) if min_lines_overrides else ruleset.checks
    sarif = _scan_ruleset(ruleset, target, instruction_files=instruction_files)
    matched_pairs, match_details = _collect_sarif_matches(sarif)
    scanned_files = _resolve_scanned_files(target, instruction_files)
    return emit_expect_findings(
        checks,
        matched_pairs,
        match_details,
        scanned_files,
        scan_root=target if target.is_dir() else target.parent,
        fix_by_rule=fix_by_rule,
        skill_entries=skill_entries,
        not_evaluated=_collect_not_evaluated(sarif),
    )


def checks_per_file(
    yml_paths: list[Path],
    scan_root: Path,
    instruction_files: list[Path] | None = None,
) -> dict[str, list[str]]:
    """List compiled regex check IDs applicable to each file."""
    ruleset = compile_rules([p for p in yml_paths if p and p.exists()])
    if not ruleset.checks:
        return {}

    universal, by_pattern = _partition_checks(ruleset.checks)
    base_ids = [c.id for c in universal]

    result: dict[str, list[str]] = {}
    for file_path in instruction_files or []:
        if not file_path.is_file():
            continue
        try:
            rel = file_path.relative_to(scan_root).as_posix()
        except ValueError:
            rel = file_path.as_posix()
        path_ids = [c.id for c in _get_applicable_checks(file_path, scan_root, [], by_pattern)]
        result[rel] = base_ids + path_ids

    return result
