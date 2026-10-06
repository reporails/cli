"""Whole-map identity cache — short-circuits the entire mapper pipeline.

Keyed on the exact input identity: the sorted file set plus each file's
import-expanded, directive-stripped content hash, plus the embedding model and
schema version. On a byte-identical run this returns the finished ``RulesetMap``
directly, skipping daemon resolution and map assembly entirely — a faster path
than the per-file atom cache (`map_cache.py`), which still resolves the daemon
and re-assembles the map from the cached per-file atoms.

On a hit the daemon socket round-trip is skipped and the map is loaded straight off disk.

Cache location: ``<global cache dir>/full-map/<identity>.json``.
Invalidation: any file content change, file added/removed, a different project root, a rules
registry change, or a model / schema / atom-shape / charge change (all fold into the identity
key). Eviction: LRU by mtime when entries exceed cap.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
from pathlib import Path

from reporails_cli.core.platform.dto.ruleset import (
    EMBEDDING_MODEL,
    SCHEMA_VERSION,
    RulesetMap,
)

logger = logging.getLogger(__name__)

_MAX_ENTRIES = 32  # global cache serves all projects; one file per distinct input set


def _expanded_content_hash(path: Path) -> str:
    """Hash a file the same way the pipeline does — import-expanded + directive-stripped.

    Matching `_classify_file`'s hash keeps the identity key import-aware: an
    `@path` import changing the expanded content changes the key.
    """
    from reporails_cli.core.cache.map_cache import content_hash
    from reporails_cli.core.lint.suppression import strip_directives
    from reporails_cli.core.mapper.imports import expand_imports

    raw = path.read_text(encoding="utf-8", errors="replace")
    return content_hash(strip_directives(expand_imports(raw, path)))


def _registry_fingerprint() -> str:
    """Content hash over the agent-registry configs the mapper classifies files against.

    Every file's ``loading`` / ``scope`` / ``globs`` / ``agent`` is read from the
    ``<agent>/config.yml`` set under the active rules path — the same glob the mapper's
    registry loader uses. That set is mutable between runs: a rules update swaps the whole
    tree, a config override redirects it, and a package upgrade ships new declarations. So it
    is a mapper INPUT like file content is, and must key the map. Hashed by content (not
    mtime) so re-installing identical rules keeps the cache warm.
    """
    from reporails_cli.core.platform.config.bootstrap import get_rules_path

    digest = hashlib.sha256()
    try:
        for config_path in sorted(get_rules_path().glob("*/config.yml")):
            digest.update(config_path.parent.name.encode("utf-8"))
            digest.update(config_path.read_bytes())
    except OSError:
        return "unreadable"
    return digest.hexdigest()[:16]


def compute_identity(
    paths: list[Path],
    *,
    root: Path,
    model: str = EMBEDDING_MODEL,
    schema: str = SCHEMA_VERSION,
    segmentation: str = "legacy",
) -> str:
    """Compute the identity key for a file set. Deterministic in path order + content.

    Folds the per-file atom cache version too: a mapper change that reshapes atoms
    from unchanged inputs (a new atom field) bumps that
    version, and the whole-map entry built from the old atoms must miss with it.

    ``root`` is required, not defaulted: the file-type attribution of every record is
    derived from each path relative to it, so a map built under one root must never be
    served to a run under another. A caller that cannot name its root would be silently
    storing an entry no other caller can safely reuse.
    """
    from reporails_cli.core.cache.map_cache import _CACHE_VERSION
    from reporails_cli.core.mapper.bio_tagger import multislot_fingerprint

    parts = [
        f"model={model}",
        f"schema={schema}",
        f"atoms={_CACHE_VERSION}",
        f"segmentation={segmentation}",
        f"root={root}",
        # The registry that decides each file's loading/scope/globs/agent — a rules update
        # must MISS the cached map instead of serving the pre-update classification.
        f"rules={_registry_fingerprint()}",
        # Fold the charge fingerprint — the same key the per-file cache uses. A re-export
        # with an unchanged atom shape must MISS the whole-map entry rather than serve
        # stale charges.
        f"charge={multislot_fingerprint()}",
    ]
    for path in sorted(paths, key=str):
        try:
            file_hash = _expanded_content_hash(path)
        except OSError:
            file_hash = "unreadable"
        parts.append(f"{path}\t{file_hash}")
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


class FullMapCache:
    """Disk cache of whole ``RulesetMap`` outputs keyed on input identity."""

    def __init__(self, cache_dir: Path) -> None:
        self.dir = cache_dir / "full-map"

    def _entry_path(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    def get(self, key: str) -> RulesetMap | None:
        """Return the cached map for this identity, or None on miss/corruption."""
        from reporails_cli.core.mapper.serialize import load_ruleset_map

        entry = self._entry_path(key)
        if not entry.exists():
            return None
        try:
            ruleset_map = load_ruleset_map(entry)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            logger.debug("Full-map cache entry unreadable, ignoring", exc_info=True)
            return None
        with contextlib.suppress(OSError):
            entry.touch()  # LRU: mark recently used
        return ruleset_map

    def put(self, key: str, ruleset_map: RulesetMap) -> None:
        """Store the map under this identity and enforce the LRU cap."""
        from reporails_cli.core.mapper.serialize import save_ruleset_map

        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            save_ruleset_map(ruleset_map, self._entry_path(key))
        except OSError:
            logger.debug("Full-map cache write failed", exc_info=True)
            return
        self._evict()

    def _evict(self) -> None:
        """Delete least-recently-used entries beyond the cap. Parallel writers sweep the same
        directory, so an entry listed here can be gone before it is stat'd — it is skipped,
        never raised into the caller's map."""
        dated: list[tuple[float, Path]] = []
        for entry in self.dir.glob("*.json"):
            try:
                dated.append((entry.stat().st_mtime, entry))
            except OSError:
                continue
        dated.sort(key=lambda pair: pair[0])
        for _mtime, stale in dated[:-_MAX_ENTRIES]:
            with contextlib.suppress(OSError):
                stale.unlink(missing_ok=True)
