"""Markdown link-reachability walker for the `generic` file class."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Inline `[text](path)` — the `path` group is the second `(...)`.
# Allows internal escapes; rejects URLs (anything with `://`) at the caller.
_INLINE_LINK_RE = re.compile(r"\[(?:[^\]]+)\]\(([^)]+)\)")

# Reference-definition `[ref]: path` — used to back reference-style links.
_REF_DEFINITION_RE = re.compile(r"^\s*\[(?:[^\]]+)\]:\s*(\S+)", re.MULTILINE)

# `@<path>` inline include — mirrors the pattern in
# `core/lint/mechanical/checks_advanced.py:extract_imports`/`import_depth`.
# Capture the path without the leading `@`.
_IMPORT_RE = re.compile(r"@([\w./-]+)")

# Code-span stripping — `[text](path)` inside backticks is documentation,
# not a real link. Mirror this with `checks_advanced._strip_code_spans`.
_CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")


def _strip_code_spans(text: str) -> str:
    """Remove fenced code blocks and inline code spans before link extraction."""
    text = _CODE_FENCE_RE.sub("", text)
    return _INLINE_CODE_RE.sub("", text)


@dataclass(frozen=True)
class LinkEdge:
    """One `(source, target)` link emitted by `walk_markdown_links`."""

    target: Path
    source: Path
    source_type: str
    depth: int
    verb: str


def walk_markdown_links(
    start_paths: dict[Path, str],
    project_root: Path,
    classified_paths: set[Path],
    max_depth: int = 3,
) -> list[LinkEdge]:
    """BFS outgoing Markdown links + `@<path>` imports from `start_paths`; emit one edge per `(source, target)`."""
    classified_resolved = {p.resolve() for p in classified_paths}
    project_root_resolved = project_root.resolve()

    seed_resolved: dict[Path, str] = {p.resolve(): ft for p, ft in start_paths.items() if p.exists()}
    visited: set[Path] = set(seed_resolved.keys())

    # Frontier: (resolved_path, depth_already_taken, source_type)
    # `depth_already_taken` is the depth at which this node was reached;
    # outgoing edges from this node land at depth+1.
    frontier: list[tuple[Path, int, str]] = [(resolved, 0, ft) for resolved, ft in seed_resolved.items()]

    # Per-target edges: keyed by (source, target, verb) so each distinct
    # (linking file, target, loading verb) tuple contributes one edge —
    # a file both linked AND imported by the same source yields two edges.
    edges: dict[tuple[Path, Path, str], LinkEdge] = {}

    while frontier:
        current, depth, source_type = frontier.pop(0)
        if depth >= max_depth:
            continue
        next_depth = depth + 1
        for linked, verb in _outgoing_links(current):
            resolved = linked.resolve()
            if not _is_in_tree(resolved, project_root_resolved):
                continue
            if not resolved.is_file():
                continue
            if resolved in classified_resolved:
                continue
            key = (current, resolved, verb)
            if key not in edges:
                edges[key] = LinkEdge(
                    target=resolved,
                    source=current,
                    source_type=source_type,
                    depth=next_depth,
                    verb=verb,
                )
            if resolved in visited:
                continue
            visited.add(resolved)
            # The reached file becomes a new frontier node; it carries
            # `file_type: "generic"` as the source_type for any links it
            # emits onward — once outside the seeded surface set, every
            # downstream reach is from a generic file.
            frontier.append((resolved, next_depth, "generic"))

    return list(edges.values())


def _outgoing_links(file_path: Path) -> list[tuple[Path, str]]:
    """Extract `(target_path, verb)` pairs for `.md` links and `@<path>` imports in `file_path`."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("link_walker: cannot read %s: %s", file_path, exc)
        return []

    # Strip fenced blocks only. Inline code is NOT stripped: a real link whose
    # text is backtick-wrapped (`[`name`](path)`) must survive — a common form
    # where the link text names a command, skill, or construct. Instead, skip a
    # link only when the link itself sits INSIDE an inline-code span (a literal
    # `[text](path)` example). `@<path>` imports run on the full text (imports
    # inside code spans are still imports per Claude's `@import` semantics).
    link_text = _CODE_FENCE_RE.sub("", text)
    code_spans = [(m.start(), m.end()) for m in _INLINE_CODE_RE.finditer(link_text)]

    def _in_code_span(pos: int) -> bool:
        return any(start <= pos < end for start, end in code_spans)

    base_dir = file_path.parent
    out: list[tuple[Path, str]] = []

    for match in _INLINE_LINK_RE.finditer(link_text):
        if _in_code_span(match.start()):
            continue
        target = match.group(1).strip()
        resolved = _resolve_md_target(base_dir, target)
        if resolved is not None:
            out.append((resolved, "read"))

    for match in _REF_DEFINITION_RE.finditer(link_text):
        if _in_code_span(match.start()):
            continue
        target = match.group(1).strip()
        resolved = _resolve_md_target(base_dir, target)
        if resolved is not None:
            out.append((resolved, "read"))

    for match in _IMPORT_RE.finditer(text):
        target = match.group(1).strip()
        resolved = _resolve_md_target(base_dir, target)
        if resolved is not None:
            out.append((resolved, "imported"))

    return out


def _outgoing_md_links(file_path: Path) -> list[Path]:
    """Return just the `.md` target paths from `_outgoing_links` (back-compat shim)."""
    return [target for target, _verb in _outgoing_links(file_path)]


def _resolve_md_target(base_dir: Path, target: str) -> Path | None:
    """Resolve a raw link target to a `.md` Path, or None if not eligible."""
    cleaned = _strip_anchor(target)
    if not cleaned or _looks_like_url(cleaned):
        return None
    if not cleaned.endswith(".md"):
        return None
    return (base_dir / cleaned).resolve()


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
