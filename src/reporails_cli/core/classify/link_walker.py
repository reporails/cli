"""Markdown link-reachability walker for the `generic` file class."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from reporails_cli.core.discovery.exclusions import RunExclusions
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.mapper.imports import import_refs
from reporails_cli.core.mapper.structure import link_targets, strip_anchor

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LinkEdge:
    """One `(source, target)` link emitted by `walk_markdown_links`."""

    target: Path
    source: Path
    source_type: str
    depth: int
    verb: str


def _reachability(
    project_root: Path, classified_paths: set[Path], exclusions: RunExclusions | None
) -> Callable[[Path], bool]:
    """Whether a resolved link target is a new in-tree file the run keeps."""
    classified_resolved = {safe_resolve(p) for p in classified_paths}
    project_root_resolved = safe_resolve(project_root)

    def reachable(resolved: Path) -> bool:
        return (
            _is_in_tree(resolved, project_root_resolved)
            and resolved.is_file()
            and resolved not in classified_resolved
            and not (exclusions is not None and exclusions.leaves_out(resolved))
        )

    return reachable


def _reachable_links(file_path: Path, reachable: Callable[[Path], bool]) -> list[tuple[Path, str]]:
    """The resolved `(target, verb)` pairs `file_path` links to that pass `reachable`."""
    resolved_links = ((safe_resolve(linked), verb) for linked, verb in _outgoing_links(file_path))
    return [(resolved, verb) for resolved, verb in resolved_links if reachable(resolved)]


def walk_markdown_links(
    start_paths: dict[Path, str],
    project_root: Path,
    classified_paths: set[Path],
    max_depth: int = 3,
    exclusions: RunExclusions | None = None,
) -> list[LinkEdge]:
    """BFS outgoing Markdown links + `@<path>` imports from `start_paths`; emit one edge per `(source, target)`.

    A target the run's exclusions leave out gets no edge and is not walked further; seeds are always walked.
    """
    reachable = _reachability(project_root, classified_paths, exclusions)

    seeds = {safe_resolve(p): ft for p, ft in start_paths.items() if p.exists()}
    visited: set[Path] = set(seeds)

    # Frontier: (resolved_path, depth_already_taken, source_type)
    # `depth_already_taken` is the depth at which this node was reached;
    # outgoing edges from this node land at depth+1.
    frontier: list[tuple[Path, int, str]] = [(resolved, 0, ft) for resolved, ft in seeds.items()]

    # Per-target edges: keyed by (source, target, verb) so each distinct
    # (linking file, target, loading verb) tuple contributes one edge —
    # a file both linked AND imported by the same source yields two edges.
    edges: dict[tuple[Path, Path, str], LinkEdge] = {}

    while frontier:
        current, depth, source_type = frontier.pop(0)
        if depth >= max_depth:
            continue
        for resolved, verb in _reachable_links(current, reachable):
            edges.setdefault(
                (current, resolved, verb),
                LinkEdge(target=resolved, source=current, source_type=source_type, depth=depth + 1, verb=verb),
            )
            if resolved in visited:
                continue
            visited.add(resolved)
            # The reached file becomes a new frontier node; it carries
            # `file_type: "generic"` as the source_type for any links it
            # emits onward — once outside the seeded surface set, every
            # downstream reach is from a generic file.
            frontier.append((resolved, depth + 1, "generic"))

    return list(edges.values())


def _outgoing_links(file_path: Path) -> list[tuple[Path, str]]:
    """Extract `(target_path, verb)` pairs for `.md` links and `@<path>` imports in `file_path`."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("link_walker: cannot read %s: %s", file_path, exc)
        return []

    base_dir = file_path.parent
    out: list[tuple[Path, str]] = []
    for verb, targets in (
        ("read", [target for _line, target in link_targets(text)]),
        ("imported", import_refs(text)),
    ):
        for target in targets:
            resolved = _resolve_md_target(base_dir, target.strip())
            if resolved is not None:
                out.append((resolved, verb))
    return out


def _resolve_md_target(base_dir: Path, target: str) -> Path | None:
    """Resolve a raw link target to a `.md` Path, or None if not eligible."""
    cleaned = strip_anchor(target)
    if not cleaned or _looks_like_url(cleaned):
        return None
    if not cleaned.endswith(".md"):
        return None
    return safe_resolve(base_dir / cleaned)


def _looks_like_url(target: str) -> bool:
    return "://" in target or target.startswith("mailto:")


def _is_in_tree(path: Path, project_root: Path) -> bool:
    try:
        path.relative_to(project_root)
    except ValueError:
        return False
    return True
