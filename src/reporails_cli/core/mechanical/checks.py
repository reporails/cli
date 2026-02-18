"""Mechanical check implementations.

Each check receives:
    root: Path to the project root
    args: Check-specific arguments from rule frontmatter
    vars: Resolved template variables from agent config

Returns a CheckResult indicating pass/fail with a message.
"""

from __future__ import annotations

import glob as globmod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _safe_float(value: Any, default: float = float("inf")) -> float:
    """Safely convert a value to float, returning default on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class CheckResult:
    """Result of a single mechanical check."""

    passed: bool
    message: str
    annotations: dict[str, Any] | None = None  # D->M metadata (e.g., discovered_imports)
    location: str | None = None  # Per-file location override (e.g., "SKILL.md:0")


def _resolve_path(template: str, vars: dict[str, str | list[str]]) -> str:
    """Resolve template variables in a path string."""
    result = template
    for key, value in vars.items():
        placeholder = "{{" + key + "}}"
        if placeholder in result:
            if isinstance(value, list):
                result = result.replace(placeholder, value[0] if value else "")
            else:
                result = result.replace(placeholder, str(value))
    return result


_glob_cache: dict[tuple[str, str], list[Path]] = {}


def _resolve_glob_targets(pattern: str, root: Path) -> list[Path]:
    """Resolve a glob pattern relative to root (cached per session)."""
    key = (pattern, str(root))
    cached = _glob_cache.get(key)
    if cached is not None:
        return cached
    resolved = str(root / pattern)
    result = [Path(p) for p in globmod.glob(resolved, recursive=True)]
    _glob_cache[key] = result
    return result


def _get_target_patterns(
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> list[str]:
    """Get file patterns from args or vars."""
    path_pattern = args.get("path", "")
    if path_pattern:
        return [_resolve_path(str(path_pattern), vars)]

    patterns = vars.get("instruction_files", [])
    if isinstance(patterns, str):
        patterns = [patterns]
    return list(patterns)


def _expand_file_pattern(
    pattern: str,
    vars: dict[str, str | list[str]],
) -> list[str]:
    """Expand a file glob pattern that may reference a list variable.

    If pattern is exactly "{{key}}" and key maps to a list, returns all
    elements. Otherwise resolves as a single string via _resolve_path.
    """
    for key, value in vars.items():
        placeholder = "{{" + key + "}}"
        if pattern == placeholder and isinstance(value, list):
            return list(value)
    return [_resolve_path(pattern, vars)]


def file_exists(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that at least one file matching the target pattern exists."""
    for pattern in _get_target_patterns(args, vars):
        if _resolve_glob_targets(pattern, root):
            return CheckResult(passed=True, message="File found")
    return CheckResult(passed=False, message="No matching files found")


def directory_exists(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that a directory exists."""
    path = _resolve_path(str(args.get("path", "")), vars)
    if (root / path).is_dir():
        return CheckResult(passed=True, message=f"Directory exists: {path}")
    return CheckResult(passed=False, message=f"Directory not found: {path}")


def directory_contains(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that a directory contains at least min_count files."""
    path = _resolve_path(str(args.get("path", "")), vars)
    pattern = str(args.get("pattern", "*"))
    min_count = int(args.get("min", 1))
    target = root / path
    if not target.is_dir():
        return CheckResult(passed=False, message=f"Directory not found: {path}")
    matches = list(target.glob(pattern))
    if len(matches) >= min_count:
        return CheckResult(passed=True, message=f"Found {len(matches)} file(s)")
    return CheckResult(passed=False, message=f"Found {len(matches)}, need {min_count}")


def git_tracked(
    root: Path,
    _args: dict[str, Any],
    _vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that the project is git-tracked.

    In test fixtures, .git_marker stands in for .git (git cannot track .git paths).
    """
    if (root / ".git").exists() or (root / ".git_marker").exists():
        return CheckResult(passed=True, message="Git repository detected")
    return CheckResult(passed=False, message="Not a git repository")


def frontmatter_key(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that files have a specific YAML frontmatter key."""
    import yaml

    key = str(args.get("key", ""))
    for pattern in _get_target_patterns(args, vars):
        for match in _resolve_glob_targets(pattern, root):
            if not match.is_file():
                continue
            try:
                content = match.read_text(encoding="utf-8")
                # Quick frontmatter parse
                if content.startswith("---"):
                    end = content.find("---", 3)
                    if end > 0:
                        fm = yaml.safe_load(content[3:end])
                        if isinstance(fm, dict) and key in fm:
                            return CheckResult(passed=True, message=f"Key '{key}' found")
            except (OSError, ValueError):
                continue
    return CheckResult(passed=False, message=f"Frontmatter key '{key}' not found")


def file_count(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that file count is within bounds."""
    min_count = int(args.get("min", 0))
    max_count = _safe_float(args.get("max"), float("inf"))
    raw_pattern = str(args.get("pattern", "**/*"))
    all_files: set[Path] = set()
    for pattern in _expand_file_pattern(raw_pattern, vars):
        all_files.update(m for m in _resolve_glob_targets(pattern, root) if m.is_file())
    count = len(all_files)
    if min_count <= count <= max_count:
        return CheckResult(passed=True, message=f"File count {count} within bounds")
    return CheckResult(passed=False, message=f"File count {count} outside bounds")


def line_count(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that file line count is within bounds."""
    max_lines = _safe_float(args.get("max"), float("inf"))
    min_lines = int(args.get("min", 0))
    for pattern in _get_target_patterns(args, vars):
        for match in _resolve_glob_targets(pattern, root):
            if not match.is_file():
                continue
            try:
                rel = str(match.relative_to(root)) if match.is_relative_to(root) else match.name
                count = len(match.read_text(encoding="utf-8").splitlines())
                if count > max_lines:
                    return CheckResult(
                        passed=False,
                        message=f"{match.name}: {count} lines exceeds max {max_lines}",
                        location=f"{rel}:0",
                    )
                if count < min_lines:
                    return CheckResult(
                        passed=False,
                        message=f"{match.name}: {count} lines below min {min_lines}",
                        location=f"{rel}:0",
                    )
            except OSError as e:
                return CheckResult(passed=False, message=f"Error reading {match.name}: {e}")
    return CheckResult(passed=True, message="Line counts within bounds")


def byte_size(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that file size is within bounds."""
    max_bytes = _safe_float(args.get("max"), float("inf"))
    min_bytes = int(_safe_float(args.get("min", 0), 0))
    for pattern in _get_target_patterns(args, vars):
        for match in _resolve_glob_targets(pattern, root):
            if not match.is_file():
                continue
            rel = str(match.relative_to(root)) if match.is_relative_to(root) else match.name
            size = match.stat().st_size
            if size > max_bytes:
                return CheckResult(passed=False, message=f"{match.name}: {size}B exceeds max", location=f"{rel}:0")
            if size < min_bytes:
                return CheckResult(passed=False, message=f"{match.name}: {size}B below min", location=f"{rel}:0")
    return CheckResult(passed=True, message="File sizes within bounds")


# Import advanced checks for re-export and registry registration
from reporails_cli.core.mechanical.checks_advanced import (  # noqa: E402
    aggregate_byte_size,
    content_absent,
    directory_file_types,
    extract_imports,
    frontmatter_valid_glob,
    import_depth,
    path_resolves,
)

# Registry of mechanical checks
MECHANICAL_CHECKS: dict[str, Any] = {
    "file_exists": file_exists,
    "directory_exists": directory_exists,
    "directory_contains": directory_contains,
    "git_tracked": git_tracked,
    "frontmatter_key": frontmatter_key,
    "file_count": file_count,
    "line_count": line_count,
    "byte_size": byte_size,
    "path_resolves": path_resolves,
    "extract_imports": extract_imports,
    "aggregate_byte_size": aggregate_byte_size,
    "import_depth": import_depth,
    "directory_file_types": directory_file_types,
    "frontmatter_valid_glob": frontmatter_valid_glob,
    "content_absent": content_absent,
}
