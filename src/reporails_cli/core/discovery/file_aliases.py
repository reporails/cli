"""File-alias map for discovered instruction files.

Collapses instruction files that are the same physical file (symlink → one
inode) or the same content within one directory (a manual AGENTS.md/CLAUDE.md
copy) into a canonical path plus its aliases, and caches the map per project
root so the display layer can render ``name (+alias)`` labels.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path

from reporails_cli.core.discovery.walk import has_symlink_loop, safe_resolve

logger = logging.getLogger(__name__)

# Cache keyed on project root; cleared alongside the agent cache on --refresh.
_alias_cache: dict[str, dict[Path, list[Path]]] = {}


def clear_alias_cache() -> None:
    """Clear the per-project alias-map cache."""
    _alias_cache.clear()


def _dedupe_symlinks(paths: list[Path]) -> tuple[list[Path], dict[Path, list[Path]]]:
    """Group paths by `Path.resolve()` and pick the alphabetically-first per group.

    Identical path strings inside a group (the same file discovered by multiple
    agents) collapse to one entry — they would otherwise show up as `+self`
    aliases of themselves in the display. A path whose symlinks loop names no file and is dropped.
    """
    by_canonical: dict[Path, list[Path]] = {}
    for p in paths:
        if has_symlink_loop(p):
            logger.warning("Circular symlink detected: %s — file will be skipped", p)
            continue
        by_canonical.setdefault(safe_resolve(p), []).append(p)

    representatives: list[Path] = []
    aliases: dict[Path, list[Path]] = {}
    for group in by_canonical.values():
        unique = sorted(set(group))
        representatives.append(unique[0])
        if len(unique) > 1:
            aliases[unique[0]] = unique[1:]
    return representatives, aliases


def _dedupe_with_aliases(paths: Iterable[Path]) -> tuple[list[Path], dict[Path, list[Path]]]:
    """Dedupe input paths by canonical resolved path (symlinks → one inode).

    Multi-agent projects often expose the same physical file via several agent
    surfaces — `.claude/skills/` symlinked to `.agents/skills/`. Without dedup
    that file is scanned and scored once per surface, inflating findings.

    Symlinks are safe to collapse at discovery time because they resolve to
    a single physical file and therefore classify identically under every
    agent's file_types. Same-directory content-hash dedup is NOT done here
    because manual AGENTS.md/CLAUDE.md pairs classify under different agents'
    `main` patterns — dropping one would suppress that agent's rules. Display
    handles those via `compute_same_dir_content_aliases` instead.

    Returns (canonical_paths, aliases). `aliases[canonical]` lists the dropped
    symlinked paths that resolve to the same inode as `canonical`.
    """
    representatives, aliases = _dedupe_symlinks(list(paths))
    return sorted(representatives), aliases


def compute_same_dir_content_aliases(paths: Iterable[Path]) -> dict[Path, list[Path]]:
    """Group paths by (parent_dir, content hash); return alias map.

    Display-time helper for collapsing manually-maintained AGENTS.md/CLAUDE.md
    pairs (and similar) into one visual row without dropping them from
    classification. Restricted to same-directory pairs so two unrelated
    identical files elsewhere in the tree are never merged. Uses
    `cache.content_hash` so the truncated SHA-256 keyspace matches every other
    content-keyed cache in the codebase.
    """
    from reporails_cli.core.cache import content_hash

    by_parent: dict[Path, list[Path]] = {}
    for p in paths:
        by_parent.setdefault(p.parent, []).append(p)
    aliases: dict[Path, list[Path]] = {}
    for siblings in by_parent.values():
        if len(siblings) < 2:
            continue
        by_hash: dict[str, list[Path]] = {}
        for s in siblings:
            try:
                key = content_hash(s)
            except OSError:
                key = f"__unhashable__:{s}"
            by_hash.setdefault(key, []).append(s)
        for hash_group in by_hash.values():
            if len(hash_group) < 2:
                continue
            ordered = sorted(hash_group)
            aliases[ordered[0]] = ordered[1:]
    return aliases


def _alias_cache_key(target: Path) -> str:
    """Project-root cache key — matches `_agent_cache` keying so both invalidate
    together on `--refresh`."""
    return str(safe_resolve(target))


def _store_alias_cache(target: Path, aliases: dict[Path, list[Path]]) -> None:
    """Cache aliases keyed by project root so the display layer can look them up."""
    _alias_cache[_alias_cache_key(target)] = aliases


def get_file_aliases(target: Path) -> dict[Path, list[Path]]:
    """Return the file-alias map produced by the most recent discovery for `target`.

    Maps a canonical instruction-file path (absolute) to the list of duplicate
    paths that share its physical file (symlink) or its content within the
    same directory (manual copy). Display layer queries this to render
    `name (+alias, +alias)` labels for deduplicated entries.
    """
    return _alias_cache.get(_alias_cache_key(target), {})
