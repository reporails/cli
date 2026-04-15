"""Per-file atom and embedding cache for incremental map updates.

Stores classified atoms and int8 embeddings keyed by content hash.
On subsequent runs, unchanged files skip tokenization and embedding
entirely. Only re-clustering runs every time (cheap, depends on full
atom set).

Cache location: .ails/.cache/map-cache.json
Invalidation: content hash mismatch, model name change, schema version change.
"""

from __future__ import annotations

import json
import logging
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
_MAX_CACHE_ENTRIES = 500  # enough for large monorepos


@dataclass
class CachedFileEntry:
    """Cached tokenization + embedding result for a single file."""

    content_hash: str
    atoms: list[dict[str, Any]] = field(default_factory=list)


class MapCache:
    """Per-file atom cache with content-hash keying.

    Usage:
        cache = MapCache(project_root / ".ails" / ".cache")
        cache.load()
        entry = cache.get("sha256:abc...")
        if entry is None:
            atoms = tokenize(content)
            cache.put(content_hash, CachedFileEntry(content_hash, [asdict(a) for a in atoms]))
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
            "entries": {chash: {"atoms": entry.atoms} for chash, entry in self._entries.items()},
        }
        tmp = self.cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        tmp.replace(self.cache_path)
        self._dirty = False
        logger.debug("Map cache saved: %d entries", len(self._entries))

    def get(self, content_hash: str) -> CachedFileEntry | None:
        """Look up cached atoms by content hash. Returns None on miss."""
        return self._entries.get(content_hash)

    def put(self, content_hash: str, entry: CachedFileEntry) -> None:
        """Store atoms for a content hash."""
        self._entries[content_hash] = entry
        self._dirty = True

    def evict_stale(self, known_hashes: set[str]) -> int:
        """Remove entries not in the current file set. Returns count evicted."""
        stale = set(self._entries.keys()) - known_hashes
        for h in stale:
            del self._entries[h]
        if stale:
            self._dirty = True
        return len(stale)

    @property
    def size(self) -> int:
        """Number of cached entries."""
        return len(self._entries)


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
