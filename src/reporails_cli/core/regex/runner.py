"""Regex execution engine + SARIF output."""

from __future__ import annotations

import fnmatch
import logging
import re
import signal
from pathlib import Path, PurePosixPath
from typing import Any

from reporails_cli.core.models import LocalFinding
from reporails_cli.core.regex.compiler import (
    CombinedPattern,
    CompiledCheck,
    compile_rules,
)

logger = logging.getLogger(__name__)


def _strip_frontmatter(content: str) -> str:
    """Replace YAML frontmatter with blank lines to preserve line numbers."""
    if not content.startswith("---"):
        return content
    end = content.find("\n---", 3)
    if end == -1:
        return content
    end_of_closing = content.find("\n", end + 4)
    if end_of_closing == -1:
        end_of_closing = len(content)
    return "\n" * content[:end_of_closing].count("\n") + content[end_of_closing:]


def _find_line_number(content: str, match: re.Match[str]) -> int:
    return content[: match.start()].count("\n") + 1


def _get_snippet(match: re.Match[str], max_len: int = 200) -> str:
    text = match.group(0)
    return text[:max_len] + "..." if len(text) > max_len else text


def _file_matches_path_filter(file_path: str, path_includes: tuple[str, ...]) -> bool:
    """Check if a file path matches any of the path include patterns."""
    if not path_includes:
        return True
    filename = Path(file_path).name
    rel = file_path.lstrip("./")
    p = PurePosixPath(rel)
    for pattern in path_includes:
        if "{{" in pattern:
            continue
        if "**" in pattern:
            clean = pattern.lstrip("./")
            if p.match(clean):
                return True
            if "**/" in clean:
                collapsed = clean.replace("**/", "")
                if fnmatch.fnmatch(rel, collapsed) or fnmatch.fnmatch(filename, collapsed):
                    return True
            continue
        if any(fnmatch.fnmatch(c, pattern) for c in (file_path, filename, rel)):
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
                targets.append(ifile)
        _append_extra(seen, targets, extra_targets)
        return targets

    scan_dir = target if target.is_dir() else target.parent
    targets = list(scan_dir.rglob("*.md"))
    if not targets:
        targets = [f for f in scan_dir.rglob("*") if f.is_file() and _is_text_file(f)]
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


_REGEX_TIMEOUT_S = 0.5


class _RegexTimeoutError(Exception):
    """Raised when a regex search exceeds the time limit."""


def _alarm_handler(_signum: int, _frame: object) -> None:
    raise _RegexTimeoutError


def _safe_search(pat: re.Pattern[str], content: str) -> re.Match[str] | None:
    """Run pat.search with a signal-based timeout against catastrophic backtracking."""
    prev = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, _REGEX_TIMEOUT_S)
    try:
        return pat.search(content)
    except _RegexTimeoutError:
        logger.warning("Regex timed out after %.1fs: %s", _REGEX_TIMEOUT_S, pat.pattern[:80])
        return None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)


def _match_check(
    check: CompiledCheck,
    content: str,
    body_content: str | None = None,
) -> list[re.Match[str]]:
    """Execute a single compiled check against file content."""
    if check.body_only:
        content = body_content if body_content is not None else _strip_frontmatter(content)
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
        rel_path = str(file_path.relative_to(scan_root))
    except ValueError:
        rel_path = file_path.name

    applicable = list(universal)
    for checks in by_pattern.values():
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


def _safe_finditer(pat: re.Pattern[str], content: str) -> list[re.Match[str]]:
    """Run pat.finditer with a signal-based timeout against catastrophic backtracking."""
    prev = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, _REGEX_TIMEOUT_S)
    try:
        return list(pat.finditer(content))
    except _RegexTimeoutError:
        logger.warning("Regex finditer timed out after %.1fs: %s", _REGEX_TIMEOUT_S, pat.pattern[:80])
        return []
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)


def _retry_shadowed(
    group_to_check: dict[str, CompiledCheck],
    matched_checks: set[str],
    content: str,
    file_uri: str,
    results: list[dict[str, Any]],
    rule_defs: dict[str, dict[str, Any]],
) -> None:
    """Retry shadowed checks under a single timeout guard."""
    prev = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, _REGEX_TIMEOUT_S * 2)
    try:
        for group_name, check in group_to_check.items():
            if group_name in matched_checks:
                continue
            if check.patterns:
                m = check.patterns[0].search(content)
                if m:
                    _emit_results(check, [m], file_uri, content, results, rule_defs)
            elif check.either_patterns:
                for pat in check.either_patterns:
                    m = pat.search(content)
                    if m:
                        _emit_results(check, [m], file_uri, content, results, rule_defs)
                        break
    except _RegexTimeoutError:
        logger.warning("Shadowed check retry timed out after %.1fs", _REGEX_TIMEOUT_S * 2)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)


def _scan_combined(
    content: str,
    file_uri: str,
    combined_patterns: list[CombinedPattern],
    results: list[dict[str, Any]],
    rule_defs: dict[str, dict[str, Any]],
) -> None:
    """Scan content using combined alternation patterns for batch matching."""
    for combined in combined_patterns:
        matched_checks: set[str] = set()
        for m in _safe_finditer(combined.regex, content):
            group_name = m.lastgroup
            if group_name and group_name not in matched_checks:
                check = combined.group_to_check[group_name]
                _emit_results(check, [m], file_uri, content, results, rule_defs)
                matched_checks.add(group_name)
                if len(matched_checks) == len(combined.group_to_check):
                    break

        if len(matched_checks) < len(combined.group_to_check):
            _retry_shadowed(combined.group_to_check, matched_checks, content, file_uri, results, rule_defs)


_MAX_FILE_SIZE = 1_048_576  # 1 MB


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
        if file_path.stat().st_size > _MAX_FILE_SIZE:
            logger.debug("Skipping oversized file: %s", file_path)
            return
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return

    try:
        file_uri = str(file_path.relative_to(scan_root))
    except ValueError:
        file_uri = str(file_path)

    body_content: str | None = None
    if any(c.body_only for c in checks):
        body_content = _strip_frontmatter(content)

    if combined_patterns:
        _scan_combined(content, file_uri, combined_patterns, results, rule_defs)

    prev = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.setitimer(signal.ITIMER_REAL, _REGEX_TIMEOUT_S * len(checks))
    try:
        for check in checks:
            matches = _match_check(check, content, body_content)
            if not matches:
                continue

            if first_match_only:
                _emit_results(check, matches[:1], file_uri, content, results, rule_defs)
            else:
                _emit_results(check, matches, file_uri, content, results, rule_defs)
    except _RegexTimeoutError:
        logger.warning("File scan timed out: %s", file_path)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)


def _scan_all_targets(
    scan_targets: list[Path],
    scan_root: Path,
    universal: list[CompiledCheck],
    by_pattern: dict[str, list[CompiledCheck]],
    exclude_dirs: list[str] | None,
) -> dict[str, Any]:
    """Scan all targets and return SARIF-shaped dict."""
    results: list[dict[str, Any]] = []
    rule_defs: dict[str, dict[str, Any]] = {}
    for file_path in scan_targets:
        if not file_path.is_file() or _should_exclude(file_path, scan_root, exclude_dirs):
            continue
        individual = universal + _get_applicable_checks(file_path, scan_root, [], by_pattern)
        if not individual or not _is_text_file(file_path):
            continue
        _scan_file(file_path, scan_root, individual, results, rule_defs)
    return _build_sarif(results, list(rule_defs.values()))


def run_validation(
    yml_paths: list[Path],
    target: Path,
    extra_targets: list[Path] | None = None,
    instruction_files: list[Path] | None = None,
    exclude_dirs: list[str] | None = None,
    body_only_paths: set[Path] | None = None,
) -> dict[str, Any]:
    """Execute regex validation with specified rule configs, returns SARIF-shaped dict."""
    valid_paths = [p for p in yml_paths if p and p.exists()]
    if not valid_paths:
        return {"runs": []}

    ruleset = compile_rules(valid_paths, body_only_paths=body_only_paths)
    if not ruleset.checks:
        return {"runs": []}

    if ruleset.skipped:
        logger.warning("Skipped rules with unsupported operators: %s", ", ".join(ruleset.skipped))

    scan_targets = _resolve_scan_targets(target, instruction_files, extra_targets)
    if not scan_targets:
        return {"runs": []}

    scan_root = target if target.is_dir() else target.parent
    universal, by_pattern = _partition_checks(ruleset.checks)
    return _scan_all_targets(scan_targets, scan_root, universal, by_pattern, exclude_dirs)


def _load_check_expectations(yml_paths: list[Path]) -> tuple[dict[str, str], dict[str, str]]:
    """Load expect and message values from check definitions."""
    import yaml

    expect_map: dict[str, str] = {}
    message_map: dict[str, str] = {}
    for yml_path in yml_paths:
        if not yml_path.exists():
            continue
        try:
            data = yaml.safe_load(yml_path.read_text(encoding="utf-8"))
            for check_def in data.get("checks", []):
                if check_def.get("type") != "deterministic":
                    continue
                if check_def.get("fallback"):
                    continue
                cid = check_def.get("id", "")
                expect_map[cid] = check_def.get("expect", "present")
                message_map[cid] = check_def.get("message", "")
        except Exception:  # yaml.YAMLError or OSError; skip unreadable files
            continue
    return expect_map, message_map


def _collect_sarif_matches(
    sarif: dict[str, Any],
) -> tuple[set[tuple[str, str]], dict[tuple[str, str], tuple[int, str]]]:
    """Extract matched (check_id, file) pairs and details from SARIF output."""
    pairs: set[tuple[str, str]] = set()
    details: dict[tuple[str, str], tuple[int, str]] = {}
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            cid = result.get("ruleId", "")
            msg = result.get("message", {}).get("text", "")
            fp, ln = "", 0
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                fp = phys.get("artifactLocation", {}).get("uri", "")
                ln = phys.get("region", {}).get("startLine", 0)
                break
            pairs.add((cid, fp))
            details[(cid, fp)] = (ln, msg)
    return pairs, details


def _resolve_scanned_files(
    target: Path,
    instruction_files: list[Path] | None,
    exclude_dirs: list[str] | None,
) -> list[str]:
    """Build list of relative file paths that were scanned."""
    scan_root = target if target.is_dir() else target.parent
    scanned: list[str] = []
    for fp in _resolve_scan_targets(target, instruction_files, None):
        if fp.is_file() and not _should_exclude(fp, scan_root, exclude_dirs):
            try:
                scanned.append(str(fp.relative_to(scan_root)))
            except ValueError:
                scanned.append(str(fp))
    return scanned


def _emit_expect_findings(
    expect_map: dict[str, str],
    message_map: dict[str, str],
    matched_pairs: set[tuple[str, str]],
    match_details: dict[tuple[str, str], tuple[int, str]],
    scanned_files: list[str],
) -> list[LocalFinding]:
    """Convert expect/match results to LocalFinding list."""
    findings: list[LocalFinding] = []
    for check_id, expect in expect_map.items():
        parts = check_id.split(".")
        rule_id = f"{parts[0]}:{parts[1]}:{parts[2]}" if len(parts) >= 3 else check_id
        check_suffix = (
            f"check:{parts[parts.index('check') + 1]}"
            if "check" in parts and parts.index("check") + 1 < len(parts)
            else ""
        )
        msg = message_map.get(check_id, "")
        if expect == "absent":
            for file_path in scanned_files:
                if (check_id, file_path) in matched_pairs:
                    line, match_msg = match_details[(check_id, file_path)]
                    findings.append(
                        LocalFinding(
                            file=file_path,
                            line=line,
                            severity="warning",
                            rule=rule_id,
                            message=match_msg or msg,
                            source="m_probe",
                            check_id=check_suffix,
                        )
                    )
        else:
            findings.extend(
                LocalFinding(
                    file=file_path,
                    line=1,
                    severity="warning",
                    rule=rule_id,
                    message=msg,
                    source="m_probe",
                    check_id=check_suffix,
                )
                for file_path in scanned_files
                if (check_id, file_path) not in matched_pairs
            )
    return findings


def run_checks(
    yml_paths: list[Path],
    target: Path,
    instruction_files: list[Path] | None = None,
    exclude_dirs: list[str] | None = None,
    body_only_paths: set[Path] | None = None,
) -> list[LocalFinding]:
    """Execute regex validation and return LocalFinding list."""
    expect_map, message_map = _load_check_expectations(yml_paths)
    sarif = run_validation(
        yml_paths,
        target,
        instruction_files=instruction_files,
        exclude_dirs=exclude_dirs,
        body_only_paths=body_only_paths,
    )
    matched_pairs, match_details = _collect_sarif_matches(sarif)
    scanned_files = _resolve_scanned_files(target, instruction_files, exclude_dirs)
    return _emit_expect_findings(expect_map, message_map, matched_pairs, match_details, scanned_files)


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
            rel = str(file_path.relative_to(scan_root))
        except ValueError:
            rel = str(file_path)
        path_ids = [c.id for c in _get_applicable_checks(file_path, scan_root, [], by_pattern)]
        result[rel] = base_ids + path_ids

    return result
