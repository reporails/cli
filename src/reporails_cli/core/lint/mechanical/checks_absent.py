"""Absence checks — a forbidden file or a forbidden content pattern must not appear in the rule's scope."""

from __future__ import annotations

import re
from pathlib import Path

from reporails_cli.core.discovery.walk import walk_glob_matches
from reporails_cli.core.lint.mechanical.checks import (
    CheckArgs,
    _resolve_glob_targets,
    arg_value,
    match_type_arg,
    run_exclusions,
    target_texts,
)
from reporails_cli.core.platform.dto.checks import CheckResult
from reporails_cli.core.platform.dto.models import ClassifiedFile
from reporails_cli.core.platform.policy.matching import _prop_matches


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


def _match_type_label(match_type: str | list[str]) -> str:
    """Render `_match_type` for a human-facing message — `config/hooks`, never a list repr."""
    return "/".join(match_type) if isinstance(match_type, list) else str(match_type)


def _resolve_scope_dir(match_type: str | list[str], classified_files: list[ClassifiedFile]) -> str:
    """Resolve a scope directory from classified files matching the given type.

    `match_type` may be a list (`match: {type: [config, hooks]}`). The listed types
    are tried in SORTED order (not classified-files discovery order), each checked
    against every classified file, so the resolved directory is deterministic — it
    always anchors on the alphabetically-first type that has a classified file,
    regardless of filesystem walk order.
    """
    if not match_type:
        return ""
    types = sorted(match_type) if isinstance(match_type, list) else [match_type]
    for one_type in types:
        for cf in classified_files:
            if _prop_matches(one_type, cf.file_type):
                rel = str(cf.path.parent)
                # Extract the non-glob prefix from the relative path
                return _scope_dir_from_glob(rel)
    return ""


def file_absent(
    root: Path,
    args: CheckArgs,
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that NO file matching the pattern exists.

    When ``_match_type`` is injected (from rule.match.type), scopes the search
    to the target directory instead of the project root.
    """
    pattern = str(arg_value(args, "pattern", ""))
    if not pattern:
        return CheckResult(passed=False, message="file_absent: no pattern specified")
    match_type = match_type_arg(args)
    exclusions = run_exclusions(args, root)
    scope_dir = _resolve_scope_dir(match_type, classified_files)

    # If the rule targets a specific file type but no files of that type were
    # classified, the scope cannot be resolved.  Falling through to the project
    # root would produce false positives (e.g. root README.md flagged by a
    # skill-scoped rule), so return pass.
    if match_type and not scope_dir:
        return CheckResult(passed=True, message=f"No {_match_type_label(match_type)} files classified")

    if scope_dir:
        scope_root = root / scope_dir
        direct_path = scope_root / pattern
        matches = [
            m
            for m in walk_glob_matches(scope_root, f"**/{pattern}", exclusions.feature_walk_dirs)
            if not exclusions.leaves_out(m)
        ]
    else:
        direct_path = root / pattern
        matches = _resolve_glob_targets(pattern, root, exclusions)
    if matches:
        name = matches[0].relative_to(root).as_posix() if matches[0].is_relative_to(root) else matches[0].name
        return CheckResult(passed=False, message=f"Forbidden file exists: {name}")
    if direct_path.exists() and not exclusions.leaves_out(direct_path):
        rel = f"{scope_dir}/{pattern}" if scope_dir else pattern
        return CheckResult(passed=False, message=f"Forbidden file exists: {rel}")
    return CheckResult(passed=True, message="Forbidden file not found")


def content_absent(
    root: Path,
    args: CheckArgs,
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that a regex pattern does NOT appear in matching files."""
    pattern = str(arg_value(args, "pattern", ""))
    if not pattern:
        return CheckResult(passed=False, message="content_absent: no pattern specified")
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return CheckResult(passed=False, message=f"content_absent: invalid regex: {e}")
    for match, content in target_texts(args, classified_files, root):
        if compiled.search(content):
            return CheckResult(passed=False, message=f"{match.name}: forbidden pattern found")
    return CheckResult(passed=True, message="Forbidden pattern not found")
