"""Markdown link-reachability walker for the `generic` file class.

REQ-025 Phase C: when `generic_scanning: true` is set in `.ails/config.yml`,
the classifier extends its file-type assignment by BFS-walking outgoing
Markdown links from each classified instruction file. Files reached
transitively that live in the project tree but aren't already classified
get `file_type: "generic"`. This catches carryovers, ADRs, sys/ docs,
knowledge docs, learning entries, and per-agent memory entries that an
agent reads as instruction input but that don't have their own canonical
capability path.

The walker is agent-agnostic by construction — it doesn't read agent
configs or hardcode per-agent paths. Anything an existing classified file
points at via a relative `[text](path.md)` or reference-style link is in
scope; anything outside the project tree is skipped.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Inline `[text](path)` — the `path` group is the second `(...)`.
# Allows internal escapes; rejects URLs (anything with `://`) at the caller.
_INLINE_LINK_RE = re.compile(r"\[(?:[^\]]+)\]\(([^)]+)\)")

# Reference-definition `[ref]: path` — used to back reference-style links.
_REF_DEFINITION_RE = re.compile(r"^\s*\[(?:[^\]]+)\]:\s*(\S+)", re.MULTILINE)


def walk_markdown_links(
    start_paths: set[Path],
    project_root: Path,
    classified_paths: set[Path],
    max_depth: int = 3,
) -> set[Path]:
    """BFS outgoing Markdown links from `start_paths`; return newly reached `.md` paths.

    Files reachable from `start_paths` that:
      - live inside `project_root`,
      - have a `.md` suffix,
      - are not already in `classified_paths`,
      - haven't been visited yet,
    are returned. The walk is bounded by `max_depth` link hops.

    Cycle-safe via `visited` set; out-of-tree links are silently skipped.
    """
    visited: set[Path] = {p.resolve() for p in start_paths if p.exists()}
    classified_resolved = {p.resolve() for p in classified_paths}
    project_root_resolved = project_root.resolve()

    frontier: list[tuple[Path, int]] = [(p, 0) for p in start_paths if p.exists()]
    found: set[Path] = set()

    while frontier:
        current, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        for linked in _outgoing_md_links(current):
            resolved = linked.resolve()
            if resolved in visited:
                continue
            visited.add(resolved)
            if resolved in classified_resolved:
                continue
            if not _is_in_tree(resolved, project_root_resolved):
                continue
            if not resolved.is_file():
                continue
            found.add(resolved)
            frontier.append((resolved, depth + 1))

    return found


def _outgoing_md_links(file_path: Path) -> list[Path]:
    """Extract relative `.md` link targets from `file_path`.

    Returns absolute paths (file_path's directory joined with the link
    target). Filters HTTP(s) URLs, anchor-only refs, and non-`.md` links.
    """
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("link_walker: cannot read %s: %s", file_path, exc)
        return []

    targets: list[str] = [m.group(1).strip() for m in _INLINE_LINK_RE.finditer(text)]
    targets.extend(m.group(1).strip() for m in _REF_DEFINITION_RE.finditer(text))

    out: list[Path] = []
    base_dir = file_path.parent
    for target in targets:
        cleaned = _strip_anchor(target)
        if not cleaned or _looks_like_url(cleaned):
            continue
        if not cleaned.endswith(".md"):
            continue
        resolved = (base_dir / cleaned).resolve()
        out.append(resolved)
    return out


def _strip_anchor(target: str) -> str:
    """Drop trailing `#anchor` and surrounding whitespace from a link target."""
    if "#" in target:
        target = target.split("#", 1)[0]
    return target.strip()


def _looks_like_url(target: str) -> bool:
    return "://" in target or target.startswith("mailto:")


def _is_in_tree(path: Path, project_root: Path) -> bool:
    try:
        path.relative_to(project_root)
    except ValueError:
        return False
    return True
