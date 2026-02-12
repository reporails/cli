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
    _expand_file_pattern,
    _get_target_patterns,
    _resolve_glob_targets,
    _resolve_path,
)


def path_resolves(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that target paths exist."""
    for pattern in _get_target_patterns(args, vars):
        if _resolve_glob_targets(pattern, root):
            return CheckResult(passed=True, message="Target paths exist")
    return CheckResult(passed=False, message="No matching paths found")


def extract_imports(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check for @import references in instruction files."""
    imports_found: list[str] = []
    for pattern in _get_target_patterns(args, vars):
        for match in _resolve_glob_targets(pattern, root):
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
    return CheckResult(passed=False, message="No imports found")


def aggregate_byte_size(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check total byte size of all matching files."""
    max_bytes = args.get("max", float("inf"))
    raw_pattern = str(args.get("pattern", "**/*"))
    all_files: set[Path] = set()
    for pattern in _expand_file_pattern(raw_pattern, vars):
        all_files.update(m for m in _resolve_glob_targets(pattern, root) if m.is_file())
    total = sum(f.stat().st_size for f in all_files)
    if total <= max_bytes:
        return CheckResult(passed=True, message=f"Total {total}B within limit")
    return CheckResult(passed=False, message=f"Total {total}B exceeds max {max_bytes}")


def import_depth(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that @import chains do not exceed max depth."""
    max_depth = int(args.get("max", 5))

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

    for pattern in _get_target_patterns(args, vars):
        for match in _resolve_glob_targets(pattern, root):
            if not match.is_file():
                continue
            deepest = follow(match, set(), 0)
            if deepest > max_depth:
                return CheckResult(
                    passed=False,
                    message=f"{match.name}: depth {deepest} exceeds max {max_depth}",
                )
    return CheckResult(passed=True, message=f"Import depth within limit ({max_depth})")


def directory_file_types(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that all files in a directory match allowed extensions."""
    path = _resolve_path(str(args.get("path", "")), vars)
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
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that YAML frontmatter path entries use valid glob syntax."""
    path = _resolve_path(str(args.get("path", "")), vars)
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


def content_absent(
    root: Path,
    args: dict[str, Any],
    vars: dict[str, str | list[str]],
) -> CheckResult:
    """Check that a regex pattern does NOT appear in matching files."""
    pattern = str(args.get("pattern", ""))
    if not pattern:
        return CheckResult(passed=False, message="content_absent: no pattern specified")
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return CheckResult(passed=False, message=f"content_absent: invalid regex: {e}")
    for fp in _get_target_patterns(args, vars):
        for match in _resolve_glob_targets(fp, root):
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
