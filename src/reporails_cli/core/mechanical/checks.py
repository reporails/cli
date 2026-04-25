"""Mechanical check implementations."""

from __future__ import annotations

import glob as globmod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reporails_cli.core.models import ClassifiedFile


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


def _get_target_files(
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
    root: Path,
) -> list[Path]:
    """Get target file paths: args.path > args._match_type > all classified files.

    Priority:
    1. Explicit glob pattern in args["path"] — resolved against root
    2. Match type from args["_match_type"] — filter classified files by type
    3. Fallback: all classified file paths
    """
    path_pattern = args.get("path", "")
    if path_pattern:
        return _resolve_glob_targets(str(path_pattern), root)

    match_type = args.get("_match_type", "")
    if match_type and classified_files:
        matched = [cf.path for cf in classified_files if cf.file_type == match_type]
        if matched:
            return matched
        # No files of this type — return empty, don't fall back to all files.
        # A config rule shouldn't check memory files just because no config exists.
        return []

    if classified_files:
        return [cf.path for cf in classified_files]

    return []


def _get_counted_files(
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
    root: Path,
) -> set[Path]:
    """Get files for counting/sizing checks: args.pattern > classified files."""
    raw_pattern = str(args.get("pattern", ""))
    if raw_pattern:
        all_files: set[Path] = set()
        all_files.update(m for m in _resolve_glob_targets(raw_pattern, root) if m.is_file())
        return all_files

    if classified_files:
        return {cf.path for cf in classified_files if cf.path.is_file()}

    # No classified files — return empty instead of globbing entire project tree
    return set()


def file_exists(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that at least one file matching the target pattern exists."""
    files = _get_target_files(args, classified_files, root)
    if any(f.exists() for f in files):
        return CheckResult(passed=True, message="File found")
    return CheckResult(passed=False, message="No matching files found")


def directory_exists(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that a directory exists."""
    path = str(args.get("path", ""))
    if (root / path).is_dir():
        return CheckResult(passed=True, message=f"Directory exists: {path}")
    return CheckResult(passed=False, message=f"Directory not found: {path}")


def directory_contains(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that a directory contains at least min_count files."""
    path = str(args.get("path", ""))
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
    _classified_files: list[ClassifiedFile],
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
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that files have a specific YAML frontmatter key."""
    import yaml

    key = str(args.get("key", ""))
    alt_key = str(args.get("alt_key", ""))
    keys = [key] + ([alt_key] if alt_key else [])
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            if content.startswith("---"):
                end = content.find("---", 3)
                if end > 0:
                    fm = yaml.safe_load(content[3:end])
                    if isinstance(fm, dict):
                        for k in keys:
                            if k in fm:
                                return CheckResult(passed=True, message=f"Key '{k}' found")
        except (OSError, ValueError):
            continue
    label = " or ".join(f"'{k}'" for k in keys)
    return CheckResult(passed=False, message=f"Frontmatter key {label} not found")


def file_count(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that file count is within bounds."""
    min_count = int(args.get("min", 0))
    max_count = _safe_float(args.get("max"), float("inf"))
    all_files = _get_counted_files(args, classified_files, root)
    count = len(all_files)
    if min_count <= count <= max_count:
        return CheckResult(passed=True, message=f"File count {count} within bounds")
    return CheckResult(passed=False, message=f"File count {count} outside bounds")


def line_count(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that file line count is within bounds."""
    max_lines = _safe_float(args.get("max"), float("inf"))
    min_lines = int(args.get("min", 0))
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
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
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that file size is within bounds."""
    max_bytes = _safe_float(args.get("max"), float("inf"))
    min_bytes = int(_safe_float(args.get("min", 0), 0))
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
        size = match.stat().st_size
        if size > max_bytes:
            return CheckResult(passed=False, message=f"{match.name}: {size}B exceeds max", location=f"{rel}:0")
        if size < min_bytes:
            return CheckResult(passed=False, message=f"{match.name}: {size}B below min", location=f"{rel}:0")
    return CheckResult(passed=True, message="File sizes within bounds")


# Import advanced checks for re-export and registry registration
from reporails_cli.core.mechanical.checks_advanced import (  # noqa: E402
    aggregate_byte_size,
    check_import_targets_exist,
    content_absent,
    count_at_least,
    count_at_most,
    directory_file_types,
    extract_imports,
    file_absent,
    filename_matches_pattern,
    frontmatter_extra_keys,
    frontmatter_present,
    frontmatter_valid_glob,
    frontmatter_valid_yaml,
    import_depth,
    path_resolves,
    valid_markdown,
)

# Registry of mechanical checks
MECHANICAL_CHECKS: dict[str, Any] = {
    "file_exists": file_exists,
    "directory_exists": directory_exists,
    "directory_contains": directory_contains,
    "git_tracked": git_tracked,
    "frontmatter_key": frontmatter_key,
    "frontmatter_present": frontmatter_present,
    "frontmatter_valid_yaml": frontmatter_valid_yaml,
    "valid_markdown": valid_markdown,
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
    "count_at_most": count_at_most,
    "count_at_least": count_at_least,
    "check_import_targets_exist": check_import_targets_exist,
    "file_absent": file_absent,
    "filename_matches_pattern": filename_matches_pattern,
    "frontmatter_extra_keys": frontmatter_extra_keys,
    # Aliases for signal catalog naming
    "glob_match": file_exists,
    "max_line_count": line_count,
    "glob_count": file_count,
    # Aliases for rule frontmatter name → check mapping
    "file_tracked": git_tracked,
    "memory_dir_exists": directory_exists,
    "total_size_check": aggregate_byte_size,
}
