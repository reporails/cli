"""Regex execution engine + SARIF output.

Executes compiled regex checks against target files and produces
SARIF-compatible output matching the downstream pipeline format.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from pathlib import Path
from typing import Any

from reporails_cli.bundled import get_capability_patterns_path
from reporails_cli.core.models import Rule
from reporails_cli.core.regex.compiler import CompiledCheck, compile_rules

logger = logging.getLogger(__name__)


def _find_line_number(content: str, match: re.Match[str]) -> int:
    """Count newlines before match start position."""
    return content[: match.start()].count("\n") + 1


def _get_snippet(match: re.Match[str], max_len: int = 200) -> str:
    """Extract a snippet around the match for SARIF output."""
    text = match.group(0)
    return text[:max_len] + "..." if len(text) > max_len else text


def _file_matches_path_filter(file_path: str, path_includes: tuple[str, ...]) -> bool:
    """Check if a file path matches any of the path include patterns."""
    if not path_includes:
        return True
    filename = Path(file_path).name
    rel = file_path.lstrip("./")
    for pattern in path_includes:
        if "{{" in pattern:
            continue
        # Handle **/ prefix: match against filename or any relative subpath
        if pattern.startswith("**/"):
            suffix = pattern[3:]  # e.g. "*.md" from "**/*.md"
            if fnmatch.fnmatch(filename, suffix) or fnmatch.fnmatch(rel, suffix):
                return True
        if fnmatch.fnmatch(file_path, pattern):
            return True
        if fnmatch.fnmatch(filename, pattern):
            return True
        if fnmatch.fnmatch(rel, pattern):
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


def _scan_file(
    file_path: Path,
    scan_root: Path,
    checks: list[CompiledCheck],
    results: list[dict[str, Any]],
    rule_defs: dict[str, dict[str, Any]],
) -> None:
    """Scan a single file against all compiled checks, appending to results."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return

    file_uri = str(file_path)

    for check in checks:
        if check.path_includes:
            try:
                rel_path = str(file_path.relative_to(scan_root))
            except ValueError:
                rel_path = file_path.name
            if not _file_matches_path_filter(rel_path, check.path_includes):
                continue

        matches = _match_check(check, content)
        if not matches:
            continue

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


def run_validation(
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

    for file_path in scan_targets:
        if not file_path.is_file():
            continue
        if _should_exclude(file_path, scan_root, exclude_dirs):
            continue
        if not _is_text_file(file_path):
            continue
        _scan_file(file_path, scan_root, ruleset.checks, results, rule_defs)

    return _build_sarif(results, list(rule_defs.values()))


def run_capability_detection(
    target: Path,
    extra_targets: list[Path] | None = None,
    instruction_files: list[Path] | None = None,
) -> dict[str, Any]:
    """Run capability detection using bundled patterns.

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

    return run_validation(
        [patterns_path],
        target,
        extra_targets=extra_targets,
        instruction_files=instruction_files,
    )


def get_rule_yml_paths(rules: dict[str, Rule]) -> list[Path]:
    """Get list of .yml paths for rules that have them and exist.

    Args:
        rules: Dict of rules

    Returns:
        List of paths to existing .yml files
    """
    return [r.yml_path for r in rules.values() if r.yml_path is not None and r.yml_path.exists()]
