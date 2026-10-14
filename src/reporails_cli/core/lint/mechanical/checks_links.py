"""Link and import target checks — discover `@import` and markdown link references, then verify they resolve."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.lint.mechanical.checks import get_target_files
from reporails_cli.core.mapper.imports import import_target
from reporails_cli.core.mapper.structure import link_targets, strip_anchor
from reporails_cli.core.platform.dto.checks import CheckResult
from reporails_cli.core.platform.dto.models import ClassifiedFile


def check_import_targets_exist(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Check that all @import paths from metadata resolve to existing files.

    Reads `discovered_imports` from args (D check annotations, `"<file-rel>::<ref>::<line>"`
    entries). Each reference resolves against the folder of the file that holds it, as the
    agent reads it. Each file with unresolved imports is one occurrence, located on its first
    unresolved import's line.
    """
    entries: list[str] = []
    for value in args.values():
        if isinstance(value, list):
            entries = value
            break
    if not entries:
        return CheckResult(passed=True, message="No import paths to check")
    missing: dict[str, list[str]] = {}
    first_line: dict[str, str] = {}
    for raw in entries:
        parts = raw.split("::")
        if len(parts) != 3:
            continue
        src_rel, ref, line = parts
        if not import_target(ref, root / src_rel).exists():
            missing.setdefault(src_rel, []).append(ref)
            first_line.setdefault(src_rel, line)
    if missing:
        return CheckResult(
            passed=False,
            message=f"{len(missing)} file(s) with unresolved imports",
            occurrences=[
                (f"{src_rel}:{first_line[src_rel]}", f"Unresolved imports: {', '.join(refs[:5])}")
                for src_rel, refs in missing.items()
            ],
        )
    return CheckResult(passed=True, message=f"All {len(entries)} import(s) resolve")


def _is_external_link(target: str) -> bool:
    """Skip URLs (http://, mailto:, etc.) and pure anchor refs."""
    if "://" in target or target.startswith("mailto:"):
        return True
    return target.startswith("#")


def broken_link_message(target: str) -> str:
    """The finding text for a link whose target does not exist."""
    return f"Broken link — `{target}` does not exist."


def extract_markdown_links(
    root: Path,
    args: dict[str, Any],
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Discover `[text](path)` + `[ref]: path` link targets in target files.

    Annotates `discovered_markdown_links` as a list of `"<file-rel>::<target>::<line>"`
    entries; the validate step splits on `::` to resolve each target against
    the source file's parent directory and to report it on its own line.

    Filters URLs (`://`, `mailto:`), bare anchor refs (`#frag`), and absolute
    paths (`/foo`). Anchors trailing on otherwise-valid links are stripped.
    Reads links from the markdown parse (`link_targets`), the same reading the
    generic-class classifier uses, so the two disagree on no link.
    """
    annotations: list[str] = []
    for match in get_target_files(args, classified_files, root):
        if not match.is_file():
            continue
        try:
            text = match.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = match.relative_to(root).as_posix() if match.is_relative_to(root) else str(match)
        for line, raw in link_targets(text):
            cleaned = strip_anchor(raw)
            if not cleaned or _is_external_link(cleaned):
                continue
            # Absolute paths (`/foo/bar.md`) are user-system paths, not
            # project-relative; treat as out-of-scope.
            if cleaned.startswith("/"):
                continue
            annotations.append(f"{rel}::{cleaned}::{line}")
    if annotations:
        return CheckResult(
            passed=True,
            message=f"Found {len(annotations)} markdown link(s)",
            annotations={"discovered_markdown_links": annotations},
        )
    return CheckResult(passed=True, message="No markdown links found")


def check_markdown_link_targets_exist(
    root: Path,
    args: dict[str, Any],
    _classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Verify each discovered markdown link resolves to an existing path.

    Reads `discovered_markdown_links` from args (D-check annotations,
    `"<file-rel>::<target>::<line>"` entries). Each target is resolved relative
    to the source file's parent directory. Each missing target is one occurrence
    located on its own line; passes when all resolve.
    """
    entries: list[str] = []
    for value in args.values():
        if isinstance(value, list):
            entries = value
            break
    if not entries:
        return CheckResult(passed=True, message="No markdown links to check")
    missing: list[tuple[str, str]] = []
    for raw in entries:
        parts = raw.split("::")
        if len(parts) != 3:
            continue
        src_rel, target, line = parts
        src_path = root / src_rel
        base_dir = src_path.parent if src_path.exists() else root
        candidate = safe_resolve(base_dir / target)
        if not candidate.exists():
            missing.append((f"{src_rel}:{line}", broken_link_message(target)))
    if missing:
        return CheckResult(
            passed=False,
            message=f"{len(missing)} broken markdown link(s)",
            occurrences=missing,
        )
    return CheckResult(passed=True, message=f"All {len(entries)} markdown link(s) resolve")
