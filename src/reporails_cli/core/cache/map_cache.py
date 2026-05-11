"""Shared atom and embedding cache for incremental map updates.

Stores classified atoms and int8 embeddings keyed by content hash.
On subsequent runs, unchanged files skip tokenization and embedding
entirely. Only re-clustering runs every time (cheap, depends on full
atom set).

Cache location: ~/.reporails/cache/map-cache.json (global, shared across projects)
Invalidation: content hash mismatch, model name change, schema version change.
Eviction: LRU when entry count exceeds cap.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from reporails_cli.core.mapper.mapper import (
    EMBEDDING_MODEL,
    SCHEMA_VERSION,
    Atom,
)

logger = logging.getLogger(__name__)

_CACHE_VERSION = 1
_MAX_CACHE_ENTRIES = 5000  # global cache serves all projects


@dataclass
class CachedFileEntry:
    """Cached tokenization + embedding result for a single file."""

    content_hash: str
    atoms: list[dict[str, Any]] = field(default_factory=list)
    last_used: str = ""  # ISO timestamp for LRU eviction


class MapCache:
    """Global atom cache with content-hash keying and LRU eviction.

    Usage:
        cache = MapCache(get_global_cache_dir())
        cache.load()
        entry = cache.get("sha256:abc...")
        if entry is None:
            atoms = tokenize(content)
            cache.put(content_hash, CachedFileEntry(content_hash, [...]))
        cache.enforce_cap()
        cache.save()
    """

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_path = cache_dir / "map-cache.json"
        self._entries: dict[str, CachedFileEntry] = {}
        self._model: str = EMBEDDING_MODEL
        self._schema: str = SCHEMA_VERSION
        self._dirty = False

    def load(self) -> None:
        """Load cache from disk. Invalidates on model/schema mismatch."""
        if not self.cache_path.exists():
            return
        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.debug("Map cache corrupt or unreadable, starting fresh")
            return

        # Invalidate on model or schema change
        if raw.get("model") != self._model:
            logger.debug("Map cache model mismatch (%s != %s), invalidating", raw.get("model"), self._model)
            return
        if raw.get("schema") != self._schema:
            logger.debug("Map cache schema mismatch, invalidating")
            return

        entries = raw.get("entries", {})
        for chash, entry_data in entries.items():
            self._entries[chash] = CachedFileEntry(
                content_hash=chash,
                atoms=entry_data.get("atoms", []),
                last_used=entry_data.get("last_used", ""),
            )
        logger.debug("Map cache loaded: %d entries", len(self._entries))

    def save(self) -> None:
        """Save cache to disk atomically (write-to-tmp + rename)."""
        if not self._dirty:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "version": _CACHE_VERSION,
            "model": self._model,
            "schema": self._schema,
            "entries": {
                chash: {"atoms": entry.atoms, "last_used": entry.last_used} for chash, entry in self._entries.items()
            },
        }
        tmp = self.cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        tmp.replace(self.cache_path)
        self._dirty = False
        logger.debug("Map cache saved: %d entries", len(self._entries))

    def get(self, content_hash: str) -> CachedFileEntry | None:
        """Look up cached atoms by content hash. Touches last_used on hit."""
        entry = self._entries.get(content_hash)
        if entry is not None:
            entry.last_used = _now_iso()
            self._dirty = True
        return entry

    def put(self, content_hash: str, entry: CachedFileEntry) -> None:
        """Store atoms for a content hash."""
        entry.last_used = _now_iso()
        self._entries[content_hash] = entry
        self._dirty = True

    def enforce_cap(self) -> int:
        """Evict least-recently-used entries exceeding the cap. Returns count evicted."""
        if len(self._entries) <= _MAX_CACHE_ENTRIES:
            return 0
        sorted_entries = sorted(self._entries.items(), key=lambda kv: kv[1].last_used)
        to_evict = len(self._entries) - _MAX_CACHE_ENTRIES
        for chash, _ in sorted_entries[:to_evict]:
            del self._entries[chash]
        self._dirty = True
        return to_evict

    def evict_stale(self, known_hashes: set[str]) -> int:  # noqa: ARG002
        """Deprecated — use enforce_cap() for global cache. No-op."""
        return 0

    @property
    def size(self) -> int:
        """Number of cached entries."""
        return len(self._entries)


def _now_iso() -> str:
    """Current UTC time as compact ISO string."""
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime())


def atoms_to_dicts(atoms: list[Atom]) -> list[dict[str, Any]]:
    """Serialize atoms to dicts for cache storage."""
    result = []
    for a in atoms:
        d = asdict(a)
        # Convert tuple fields to lists for JSON
        if d.get("embedding_int8") is not None:
            d["embedding_int8"] = list(d["embedding_int8"])
        if d.get("topics"):
            d["topics"] = list(d["topics"])
        result.append(d)
    return result


def dicts_to_atoms(dicts: list[dict[str, Any]]) -> list[Atom]:
    """Deserialize atom dicts back to Atom instances."""
    atoms = []
    for d in dicts:
        # Convert lists back to tuples
        if d.get("embedding_int8") is not None:
            d["embedding_int8"] = tuple(d["embedding_int8"])
        if d.get("topics") is not None:
            d["topics"] = tuple(d["topics"])
        atoms.append(Atom(**d))
    return atoms
