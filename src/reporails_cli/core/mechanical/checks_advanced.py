# pylint: disable=too-many-lines
"""Advanced mechanical checks — content reading, import following, aggregation.

These checks are more complex than the simple structural checks in checks.py.
They are imported and registered in MECHANICAL_CHECKS by checks.py.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.mechanical.checks import (
    CheckResult,
    _get_counted_files,
    _get_target_files,
    _resolve_glob_targets,
    _safe_float,
)
from reporails_cli.core.models import ClassifiedFile


def frontmatter_present(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that at least one target file has a YAML frontmatter block."""
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            if content.startswith("---"):
                end = content.find("---", 3)
                if end > 0:
                    return CheckResult(passed=True, message="Frontmatter block found")
        except OSError:
            continue
    return CheckResult(passed=False, message="No frontmatter block found")


def frontmatter_valid_yaml(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that all frontmatter blocks contain valid YAML mappings."""
    checked = 0
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            if not content.startswith("---"):
                continue
            end = content.find("---", 3)
            if end < 0:
                continue
            checked += 1
            fm = yaml.safe_load(content[3:end])
            if not isinstance(fm, dict):
                rel = str(match.relative_to(root)) if match.is_relative_to(root) else match.name
                return CheckResult(
                    passed=False,
                    message=f"Frontmatter is not a YAML mapping in {match.name}",
                    location=f"{rel}:1",
                )
        except yaml.YAMLError as e:
            rel = str(match.relative_to(root)) if match.is_relative_to(root) else match.name
            return CheckResult(
                passed=False,
                message=f"Invalid YAML in {match.name}: {e}",
                location=f"{rel}:1",
            )
        except OSError:
            continue
    if checked == 0:
        return CheckResult(passed=True, message="No frontmatter to validate")
    return CheckResult(passed=True, message=f"All {checked} frontmatter block(s) valid")


_BROKEN_HEADING_RE = re.compile(r"^#{1,6}[^ #\n]", re.MULTILINE)


def valid_markdown(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check for structural markdown issues in target files."""
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            m = _BROKEN_HEADING_RE.search(content)
            if m:
                line_num = content[: m.start()].count("\n") + 1
                rel = str(match.relative_to(root)) if match.is_relative_to(root) else match.name
                return CheckResult(
                    passed=False,
                    message=f"Broken heading (missing space after #) in {match.name}",
                    location=f"{rel}:{line_num}",
                )
        except OSError:
            continue
    return CheckResult(passed=True, message="Markdown structure valid")


def path_resolves(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that target paths exist."""
    files = _get_target_files(args, classified_files, root)
    if files:
        return CheckResult(passed=True, message="Target paths exist")
    return CheckResult(passed=False, message="No matching paths found")


def extract_imports(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check for @import references in instruction files."""
    imports_found: list[str] = []
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            imports_found.extend(re.findall(r"@[\w./-]+", content))
        except OSError:
            continue
    if imports_found:
        return CheckResult(
            passed=True,
            message=f"Found {len(imports_found)} import(s)",
            annotations={"discovered_imports": imports_found},
        )
    # No imports is valid — nothing to validate. Pass with empty annotations
    # so check_import_targets_exist sees no work and also passes.
    return CheckResult(passed=True, message="No imports found")


def aggregate_byte_size(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check total byte size of all matching files."""
    max_bytes = _safe_float(args.get("max"), float("inf"))
    all_files = _get_counted_files(args, classified_files, root)
    total = sum(f.stat().st_size for f in all_files)
    if total <= max_bytes:
        return CheckResult(passed=True, message=f"Total {total}B within limit")
    return CheckResult(passed=False, message=f"Total {total}B exceeds max {max_bytes}")


def import_depth(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that @import chains do not exceed max depth."""
    max_depth_val = int(args.get("max", 5))

    def follow(filepath: Path, visited: set[Path], depth: int) -> int:
        if filepath in visited or not filepath.is_file():
            return depth
        visited.add(filepath)
        try:
            content = filepath.read_text(encoding="utf-8")
        except OSError:
            return depth
        refs = re.findall(r"@([\w./-]+)", content)
        max_d = depth
        for ref in refs:
            target = filepath.parent / ref
            if target.is_file():
                max_d = max(max_d, follow(target, visited, depth + 1))
        return max_d

    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        deepest = follow(match, set(), 0)
        if deepest > max_depth_val:
            return CheckResult(
                passed=False,
                message=f"{match.name}: depth {deepest} exceeds max {max_depth_val}",
            )
    return CheckResult(passed=True, message=f"Import depth within limit ({max_depth_val})")


def directory_file_types(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that all files in a directory match allowed extensions."""
    path = str(args.get("path", ""))
    extensions: list[str] = list(args.get("extensions", []))
    target = root / path
    if not target.is_dir():
        return CheckResult(passed=True, message=f"Directory not found: {path} (OK)")
    bad = [f.name for f in target.iterdir() if f.is_file() and f.suffix not in extensions]
    if bad:
        return CheckResult(passed=False, message=f"Non-{extensions} files: {', '.join(bad[:5])}")
    return CheckResult(passed=True, message=f"All files in {path} match {extensions}")


def frontmatter_valid_glob(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that YAML frontmatter path entries use valid glob syntax."""
    path = str(args.get("path", ""))
    target = root / path
    if not target.is_dir():
        return CheckResult(passed=True, message=f"Directory not found: {path} (OK)")
    for f in target.iterdir():
        if not f.is_file() or f.suffix != ".md":
            continue
        try:
            content = f.read_text(encoding="utf-8")
            if not content.startswith("---"):
                continue
            end = content.find("---", 3)
            if end < 0:
                continue
            fm = yaml.safe_load(content[3:end])
            if not isinstance(fm, dict):
                continue
            paths = fm.get("globs") or fm.get("paths") or []
            if isinstance(paths, str):
                paths = [paths]
            for p in paths:
                if not isinstance(p, str):
                    return CheckResult(passed=False, message=f"{f.name}: non-string path: {p}")
                if p.count("[") != p.count("]"):
                    return CheckResult(passed=False, message=f"{f.name}: unbalanced brackets: {p}")
        except (OSError, yaml.YAMLError):
            continue
    return CheckResult(passed=True, message="All frontmatter path entries valid")


def count_at_most(
    _root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that a metadata list has at most N entries.

    Reads a named metadata key from args (injected by pipeline from annotations).
    Args: threshold (int, default 0), plus the metadata key name -> list.
    """
    threshold = int(args.get("threshold", 0))
    items: list[str] = []
    for value in args.values():
        if isinstance(value, list):
            items = value
            break
    if len(items) <= threshold:
        return CheckResult(passed=True, message=f"Count {len(items)} within limit ({threshold})")
    return CheckResult(passed=False, message=f"Count {len(items)} exceeds max {threshold}")


def count_at_least(
    _root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that a metadata list has at least N entries.

    Reads a named metadata key from args (injected by pipeline from annotations).
    Args: threshold (int, default 1), plus the metadata key name -> list.
    """
    threshold = int(args.get("threshold", 1))
    items: list[str] = []
    for value in args.values():
        if isinstance(value, list):
            items = value
            break
    if len(items) >= threshold:
        return CheckResult(passed=True, message=f"Count {len(items)} meets minimum ({threshold})")
    return CheckResult(passed=False, message=f"Count {len(items)} below minimum {threshold}")


def check_import_targets_exist(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that all @import paths from metadata resolve to existing files.

    Reads import paths from args (injected by pipeline from D check annotations).
    Each path is resolved relative to the target instruction file's directory.
    """
    import_paths: list[str] = []
    for value in args.values():
        if isinstance(value, list):
            import_paths = value
            break
    if not import_paths:
        return CheckResult(passed=True, message="No import paths to check")
    missing: list[str] = []
    for ref in import_paths:
        clean = ref.lstrip("@")
        if not (root / clean).exists():
            missing.append(clean)
    if missing:
        return CheckResult(
            passed=False,
            message=f"Unresolved imports: {', '.join(missing[:5])}",
        )
    return CheckResult(passed=True, message=f"All {len(import_paths)} import(s) resolve")


def filename_matches_pattern(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that target filenames match a regex pattern.

    Args: pattern (regex string), path (optional glob for file targets).
    """
    pattern = str(args.get("pattern", ""))
    if not pattern:
        return CheckResult(passed=False, message="filename_matches_pattern: no pattern specified")
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return CheckResult(passed=False, message=f"filename_matches_pattern: invalid regex: {e}")
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        if not compiled.search(match.name):
            return CheckResult(
                passed=False,
                message=f"{match.name}: does not match pattern {pattern}",
            )
    return CheckResult(passed=True, message="All filenames match pattern")


def _scope_dir_from_glob(glob_pattern: str) -> str:
    """Extract the non-glob directory prefix from a glob pattern.

    >>> _scope_dir_from_glob(".claude/skills/**/*.md")
    '.claude/skills'
    >>> _scope_dir_from_glob("**/CLAUDE.md")
    ''
    """
    parts = glob_pattern.replace("\\", "/").split("/")
    dirs: list[str] = []
    for part in parts:
        if any(c in part for c in "*?[{"):
            break
        dirs.append(part)
    return "/".join(dirs)


def _resolve_scope_dir(match_type: str, classified_files: list[ClassifiedFile]) -> str:
    """Resolve a scope directory from classified files matching the given type."""
    if not match_type:
        return ""
    for cf in classified_files:
        if cf.file_type == match_type:
            rel = str(cf.path.parent)
            # Extract the non-glob prefix from the relative path
            return _scope_dir_from_glob(rel)
    return ""


def file_absent(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that NO file matching the pattern exists.

    When ``_match_type`` is injected (from rule.match.type), scopes the search
    to the target directory instead of the project root.
    """
    pattern = str(args.get("pattern", ""))
    if not pattern:
        return CheckResult(passed=False, message="file_absent: no pattern specified")
    match_type = str(args.get("_match_type", ""))
    scope_dir = _resolve_scope_dir(match_type, classified_files)

    # If the rule targets a specific file type but no files of that type were
    # classified, the scope cannot be resolved.  Falling through to the project
    # root would produce false positives (e.g. root README.md flagged by a
    # skill-scoped rule), so return pass.
    if match_type and not scope_dir:
        return CheckResult(passed=True, message=f"No {match_type} files classified")

    if scope_dir:
        search_pattern = f"{scope_dir}/**/{pattern}"
        direct_path = root / scope_dir / pattern
    else:
        search_pattern = pattern
        direct_path = root / pattern

    matches = _resolve_glob_targets(search_pattern, root)
    if matches:
        name = str(matches[0].relative_to(root)) if matches[0].is_relative_to(root) else matches[0].name
        return CheckResult(passed=False, message=f"Forbidden file exists: {name}")
    if direct_path.exists():
        rel = f"{scope_dir}/{pattern}" if scope_dir else pattern
        return CheckResult(passed=False, message=f"Forbidden file exists: {rel}")
    return CheckResult(passed=True, message="Forbidden file not found")


def content_absent(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that a regex pattern does NOT appear in matching files."""
    pattern = str(args.get("pattern", ""))
    if not pattern:
        return CheckResult(passed=False, message="content_absent: no pattern specified")
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return CheckResult(passed=False, message=f"content_absent: invalid regex: {e}")
    for match in _get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            content = match.read_text(encoding="utf-8")
            if compiled.search(content):
                return CheckResult(
                    passed=False,
                    message=f"{match.name}: forbidden pattern found",
                )
        except OSError:
            continue
    return CheckResult(passed=True, message="Forbidden pattern not found")
