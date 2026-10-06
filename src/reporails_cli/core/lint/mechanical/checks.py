"""Mechanical check implementations."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.agents import load_project_exclude_dirs
from reporails_cli.core.discovery.walk import safe_resolve, walk_glob_matches
from reporails_cli.core.mapper.skills import skill_entry_paths
from reporails_cli.core.platform.dto.checks import CheckResult
from reporails_cli.core.platform.dto.models import ClassifiedFile
from reporails_cli.core.platform.utils.utils import read_frontmatter_file


def _safe_float(value: Any, default: float = float("inf")) -> float:
    """Safely convert a value to float, returning default on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _resolve_glob_targets(pattern: str, root: Path) -> list[Path]:
    """Resolve a glob pattern relative to root: the regular files it matches, not entering
    any folder in the project's exclude_dirs.

    Hidden folders such as `.claude/` and `.cursor/` are walked, so `**/*.md`
    matches files under them. The intersection with `classified_files` in
    `get_target_files` bounds the result back to in-scope instruction files.
    """
    return list(walk_glob_matches(root, pattern, load_project_exclude_dirs(root)))


def get_target_files(
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
    root: Path,
) -> list[Path]:
    """Get targets (see `_select_targets`); `entry_only` then keeps a skill's entry files."""
    targets = _select_targets(args, classified_files, root)
    if args.get("entry_only"):
        return _keep_skill_entries(targets, classified_files)
    return targets


def _keep_skill_entries(targets: list[Path], classified_files: list[ClassifiedFile]) -> list[Path]:
    """Keep the targets that are a skill's entry file; all of them when no classified file records a skill."""
    entries = skill_entry_paths(classified_files)
    if entries is None:
        return targets
    return [p for p in targets if safe_resolve(p) in entries]


def _select_targets(
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
    root: Path,
) -> list[Path]:
    """Get target file paths: args.path ∩ classified > args._match_type > all classified files.

    Priority:
    1. Explicit glob pattern in args["path"] — resolved against root, then
       intersected with `classified_files` when that set is non-empty so
       a targeted `ails check <capability>:<name>` actually narrows the
       glob to in-scope files. Without the intersection, `path: "**/*.md"`
       would bypass capability narrowing and surface cross-file findings
       (e.g. broken links in `CLAUDE.md`) under unrelated focus targets.
    2. Match type from args["_match_type"] — filter classified files by type
    3. Fallback: all classified file paths
    """
    path_pattern = args.get("path", "")
    if path_pattern:
        glob_targets = _resolve_glob_targets(str(path_pattern), root)
        if not classified_files:
            return glob_targets
        allowed: set[Path] = set()
        for cf in classified_files:
            allowed.add(safe_resolve(cf.path))
        narrowed: list[Path] = []
        for p in glob_targets:
            resolved = safe_resolve(p)
            if resolved in allowed:
                narrowed.append(p)
        return narrowed

    match_type = args.get("_match_type", "")
    if match_type and classified_files:
        # `match.type` may be a list (`{type: [config, hooks]}`) — compare through
        # the shared matching predicate, never `==`, or a list-valued type matches
        # nothing and the check reports "No matching files found" on a file it owns.
        from reporails_cli.core.platform.policy.matching import _prop_matches

        matched = [cf.path for cf in classified_files if _prop_matches(match_type, cf.file_type)]
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
    files = get_target_files(args, classified_files, root)
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


def _is_set(value: Any) -> bool:
    """A frontmatter value that says something: not absent, null or blank text."""
    return value is not None and (not isinstance(value, str) or bool(value.strip()))


def _frontmatter_key_gap(path: Path, keys: list[str], args: dict[str, Any], label: str) -> str | None:
    """Why `path` lacks every one of `keys` in its frontmatter block; None when one is defined.

    A block that does not read as YAML is not a gap: `frontmatter_valid_yaml` reports it.
    """
    read = read_frontmatter_file(path, lenient=bool(args.get("lenient", False)))
    if read is not None and read.problem is not None:
        return None
    if read is not None and read.data is not None and any(_is_set(read.data.get(k)) for k in keys):
        return None
    return f"Frontmatter key {label} not found"


def frontmatter_key(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that every target file has a specific YAML frontmatter key.

    Each file missing every listed key is its own occurrence, so one
    compliant sibling in a multi-file match set (e.g. a second Copilot
    `*.instructions.md`) does not hide another file's missing key.
    """
    key = str(args.get("key", ""))
    alt_key = str(args.get("alt_key", ""))
    keys = [key] + ([alt_key] if alt_key else [])
    label = " or ".join(f"'{k}'" for k in keys)
    targets = [m for m in get_target_files(args, classified_files, root) if m.is_file()]
    if not targets:
        return CheckResult(passed=False, message=f"Frontmatter key {label} not found")

    missing: list[tuple[str, str]] = []
    for match in targets:
        gap = _frontmatter_key_gap(match, keys, args, label)
        if gap is not None:
            rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
            missing.append((f"{rel}:0", gap))

    if missing:
        return CheckResult(
            passed=False,
            message=f"{len(missing)} file(s) missing frontmatter key {label}",
            occurrences=missing,
        )
    return CheckResult(passed=True, message=f"Key {label} found in all target file(s)")


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
    for match in get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
            count = len(match.read_text(encoding="utf-8", errors="replace").splitlines())
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
    for match in get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else match.name
        size = match.stat().st_size
        if size > max_bytes:
            return CheckResult(passed=False, message=f"{match.name}: {size}B exceeds max", location=f"{rel}:0")
        if size < min_bytes:
            return CheckResult(passed=False, message=f"{match.name}: {size}B below min", location=f"{rel}:0")
    return CheckResult(passed=True, message="File sizes within bounds")


# Import advanced checks for registry registration
from reporails_cli.core.lint.mechanical.checks_advanced import (  # noqa: E402
    aggregate_byte_size,
    check_import_targets_exist,
    check_markdown_link_targets_exist,
    content_absent,
    count_at_least,
    count_at_most,
    directory_file_types,
    extract_imports,
    extract_markdown_links,
    file_absent,
    filename_matches_pattern,
    frontmatter_extra_keys,
    frontmatter_matches_dirname,
    frontmatter_present,
    frontmatter_valid_glob,
    frontmatter_valid_yaml,
    import_depth,
    path_resolves,
    skill_entrypoint_present,
    valid_markdown,
)
from reporails_cli.core.lint.mechanical.hook_handlers import hook_handlers  # noqa: E402

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
    "extract_markdown_links": extract_markdown_links,
    "check_markdown_link_targets_exist": check_markdown_link_targets_exist,
    "file_absent": file_absent,
    "filename_matches_pattern": filename_matches_pattern,
    "frontmatter_extra_keys": frontmatter_extra_keys,
    "frontmatter_matches_dirname": frontmatter_matches_dirname,
    "skill_entrypoint_present": skill_entrypoint_present,
    "hook_handlers": hook_handlers,
    # Aliases for signal catalog naming
    "glob_match": file_exists,
    "max_line_count": line_count,
    "glob_count": file_count,
    # Aliases for rule frontmatter name → check mapping
    "file_tracked": git_tracked,
    "memory_dir_exists": directory_exists,
    "total_size_check": aggregate_byte_size,
}
