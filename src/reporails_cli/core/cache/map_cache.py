"""Shared atom and embedding cache for incremental map updates.

Stores classified atoms and int8 embeddings keyed by content hash, plus the
int8 embedding of a skill or agent file's frontmatter description.
On subsequent runs, unchanged files skip tokenization and embedding
entirely.

Cache location: ~/.reporails/cache/map-atoms/<identity-digest>/<hash>.json
(global, shared across projects) — one small JSON file per cached file-entry.
A run reads only the shards for the files it maps, never a whole-corpus blob;
identical files shared across projects hit the same shard (cross-project dedup).
Invalidation: content hash mismatch (a different shard), model name change,
schema version change, charge-model fingerprint change — the last three fold
into the <identity-digest> subdir, so a change lands in a fresh subdir; a subdir
not used for 30 days is removed, one in use by another configuration is kept.
Eviction: mtime-LRU when the shard count exceeds cap.
A legacy `map-cache.json` monolith is migrated to shards once, then removed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.platform.dto.ruleset import (
    EMBEDDING_MODEL,
    SCHEMA_VERSION,
    Atom,
    AtomSlots,
    FileRecord,
)

logger = logging.getLogger(__name__)


def content_hash(text: str) -> str:
    """Compute SHA-256 hash of text with sha256: prefix."""
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def file_cache_key(
    path: Path,
    chash: str,
    line_map: list[int],
    origins: list[tuple[Path, int] | None],
) -> str:
    """Per-file cache key: the expanded content hash, plus the file's own coordinates.

    Cached atoms carry source line numbers and import origins that belong to the
    file that wrote them. A file whose lines map one-to-one onto its content and
    that imports nothing has no coordinates of its own, so its key is the bare
    content hash and byte-identical plain files share one entry. A file with
    imports folds its line map and import origins into the key, so two files that
    expand to the same content never serve each other's coordinates.
    """
    plain = not any(o is not None for o in origins) and line_map == list(range(1, len(line_map) + 1))
    if plain:
        return chash
    base = safe_resolve(path).parent
    signature = json.dumps(
        [line_map, [None if o is None else [Path(os.path.relpath(o[0], base)).as_posix(), o[1]] for o in origins]],
        separators=(",", ":"),
    )
    return f"{chash}+{hashlib.sha256(signature.encode('utf-8')).hexdigest()[:16]}"


def cache_key_for_path(path: Path) -> str:
    """The per-file cache key the mapper uses for `path`."""
    from reporails_cli.core.lint.suppression import strip_directives
    from reporails_cli.core.mapper.imports import expand_imports_with_origins

    expanded, line_map, origins = expand_imports_with_origins(path.read_text(encoding="utf-8", errors="replace"), path)
    return file_cache_key(path, content_hash(strip_directives(expanded)), line_map, origins)


# Atom field names, used to drop keys a prior CLI version cached but the current
# Atom no longer declares, so a stale-shape entry rehydrates instead of crashing
# Atom(**d) on an unexpected keyword.
_ATOM_FIELD_NAMES = frozenset(Atom.model_fields)

# AtomSlots fields carrying the span-coordinate half (offsets + per-span
# confidence) — the only part of `slots` that survives the cache round-trip.
# Slot TEXT (subject/predicate/object/scope strings) stays cli-local-per-run
# and is never written to `slot_coords`: slot text stays local to the run.
_SLOT_COORD_FIELDS = (
    "subject_span",
    "predicate_span",
    "object_span",
    "scope_span",
    "subject_conf",
    "predicate_conf",
    "object_conf",
    "scope_conf",
)
_SLOT_SPAN_FIELDS = ("subject_span", "predicate_span", "object_span", "scope_span")

# Bump when the cached atom shape or the way atoms are read changes: every entry
# stored under an older version then misses and is rebuilt on the next run.
_CACHE_VERSION = 31
_MAX_CACHE_ENTRIES = 5000  # global cache serves all projects
_STALE_IDENTITY_DAYS = 30  # a sibling configuration's folder unused this long is removed


@dataclass
class CachedFileEntry:
    """Cached tokenization + embedding result for a single file."""

    content_hash: str
    atoms: list[dict[str, Any]] = field(default_factory=list)
    last_used: str = ""  # ISO timestamp for LRU eviction
    description_embedding: list[int] | None = None  # int8 embedding of the frontmatter description


def _identity_digest(version: int, model: str, schema: str, segmentation: str, charge: str) -> str:
    """Stable short digest of the cache-identity fields.

    Folds cache-format version + model + schema + segmentation + charge into one
    subdir name. It carries no project path, so identical files across projects
    resolve to the same shard (cross-project dedup); a change to any identity
    field lands in a fresh subdir and the stale one ages out under the cap.
    """
    raw = f"{version}|{model}|{schema}|{segmentation}|{charge}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _shard_payload(entry: CachedFileEntry) -> dict[str, Any]:
    """The JSON body of one shard."""
    payload: dict[str, Any] = {"atoms": entry.atoms, "last_used": entry.last_used}
    if entry.description_embedding is not None:
        payload["description_embedding"] = entry.description_embedding
    return payload


def _shard_filename(content_hash: str) -> str:
    """Filesystem-safe shard filename for a content hash.

    Content hashes may carry a `sha256:` prefix; `:` and `/` are not portable in
    filenames, so replace them (the hex charset means no distinct hash collides).
    """
    return content_hash.replace(":", "_").replace("/", "_") + ".json"


class MapCache:
    """Global atom cache with content-hash keying and mtime-LRU eviction.

    Storage is one small JSON file per cached file-entry, under a per-identity
    subdir: ``<cache_dir>/map-atoms/<identity-digest>/<hash>.json``. A run reads
    only the shards for the files it maps — never a whole-corpus blob — so
    per-run I/O is bounded by the mapped file set, not the total cache.

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

    def __init__(
        self,
        cache_dir: Path,
        segmentation: str = "legacy",
        charge: str = "",
    ) -> None:
        self.cache_dir = cache_dir
        # Legacy monolith path — migration source only (see `load`).
        self.cache_path = cache_dir / "map-cache.json"
        self._model: str = EMBEDDING_MODEL
        self._schema: str = SCHEMA_VERSION
        self._segmentation: str = segmentation
        # Content-hash fingerprint of the bundled classification model files.
        self._charge: str = charge
        self._digest = _identity_digest(_CACHE_VERSION, self._model, self._schema, self._segmentation, self._charge)
        self._shard_dir = cache_dir / "map-atoms" / self._digest
        # In-memory read-cache of shards touched this run; NOT a load-all.
        self._entries: dict[str, CachedFileEntry] = {}
        # Hashes whose shard write failed at put() time; retried on save().
        self._pending: set[str] = set()

    def load(self) -> None:
        """Prepare the shard dir and migrate the legacy monolith once, if present.

        Does not read shards into memory — `get` reads them lazily per hash.
        """
        self._migrate_monolith_if_present()
        self._prune_stale_identities()

    def _prune_stale_identities(self) -> None:
        """Remove sibling identity subdirs under `map-atoms/` that have gone unused.

        Another configuration (a different segmentation or tagging model, or an
        older cache version) writes its own identity subdir beside this one, and
        a project using it must keep its warm cache when this one opens. A
        sibling is removed only when none of its shards was read or written in
        the last `_STALE_IDENTITY_DAYS` days, which bounds the disk a retired
        configuration can leave behind.
        """
        parent = self._shard_dir.parent  # <cache_dir>/map-atoms
        try:
            subdirs = [d for d in parent.iterdir() if d.is_dir()]
        except OSError:
            return
        cutoff = time.time() - _STALE_IDENTITY_DAYS * 86400
        for d in subdirs:
            if d.name != self._digest and not _used_since(d, cutoff):
                with contextlib.suppress(OSError):
                    shutil.rmtree(d)

    def _migrate_monolith_if_present(self) -> None:
        """One-shot migration off the old whole-corpus `map-cache.json`.

        Storage-format change only (orthogonal to atom shape, so no
        `_CACHE_VERSION` bump). If the monolith's identity matches this cache's,
        split each entry into a shard so the warm cache survives the upgrade;
        otherwise it would invalidate anyway. Either way the monolith is removed.
        """
        if not self.cache_path.exists():
            return
        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            with contextlib.suppress(OSError):
                self.cache_path.unlink()
            return
        identity_ok = (
            raw.get("version") == _CACHE_VERSION
            and raw.get("model") == self._model
            and raw.get("schema") == self._schema
            and raw.get("segmentation", "legacy") == self._segmentation
            and raw.get("charge") == self._charge
        )
        if not identity_ok:
            # Stale identity: the monolith's atoms can never be served now, so drop it.
            with contextlib.suppress(OSError):
                self.cache_path.unlink()
            return
        entries = raw.get("entries", {})
        all_ok = True
        for chash, entry_data in entries.items():
            if not self._write_shard(
                chash,
                {"atoms": entry_data.get("atoms", []), "last_used": entry_data.get("last_used", "")},
            ):
                all_ok = False
        logger.debug("Migrated %d monolith entries to shards", len(entries))
        # Only remove the warm monolith once every shard is safely written; a
        # failed write (full disk, permissions) keeps it so the next run retries
        # the migration instead of dropping the warm cache to a cold rebuild.
        if all_ok:
            with contextlib.suppress(OSError):
                self.cache_path.unlink()
        else:
            logger.warning("Monolith migration had shard-write failures; keeping map-cache.json for retry")

    def _shard_path(self, content_hash: str) -> Path:
        return self._shard_dir / _shard_filename(content_hash)

    def _write_shard(self, content_hash: str, payload: dict[str, Any]) -> bool:
        """Atomically write one shard (mkstemp + os.replace). Never raises.

        Returns True on success. A cache write must never take down the run, so
        any `OSError` (concurrent writer, full disk, permissions) is caught and
        logged; the caller records the hash for a `save()` retry.
        """
        try:
            self._shard_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=self._shard_dir, prefix=".shard-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(json.dumps(payload, separators=(",", ":")))
                os.replace(tmp_name, self._shard_path(content_hash))
            except OSError:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except OSError:
            logger.warning("Map cache shard write failed, will retry on save", exc_info=True)
            return False
        return True

    def get(self, content_hash: str) -> CachedFileEntry | None:
        """Look up cached atoms by content hash, reading the shard on a memory miss.

        Touches the shard's mtime on a disk hit so mtime-LRU sees the access. The
        touch is a single-file `Path.touch` — cheap now that entries are separate
        files, unlike the old whole-blob rewrite a read-touch used to imply.
        """
        entry = self._entries.get(content_hash)
        if entry is not None:
            entry.last_used = _now_iso()
            return entry
        path = self._shard_path(content_hash)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        entry = CachedFileEntry(
            content_hash=content_hash,
            atoms=data.get("atoms", []),
            last_used=data.get("last_used", ""),
            description_embedding=data.get("description_embedding"),
        )
        self._entries[content_hash] = entry
        with contextlib.suppress(OSError):
            path.touch()
        entry.last_used = _now_iso()
        return entry

    def put(self, content_hash: str, entry: CachedFileEntry) -> None:
        """Store atoms for a content hash and write its shard immediately."""
        entry.last_used = _now_iso()
        self._entries[content_hash] = entry
        if self._write_shard(content_hash, _shard_payload(entry)):
            self._pending.discard(content_hash)
        else:
            self._pending.add(content_hash)

    def save(self) -> None:
        """Retry any shard writes that failed at `put()` time.

        Shards are written eagerly on `put`, so a clean run leaves nothing to do
        here; this only retries writes an earlier `OSError` deferred.
        """
        for chash in list(self._pending):
            entry = self._entries.get(chash)
            if entry is None:
                self._pending.discard(chash)
                continue
            if self._write_shard(chash, _shard_payload(entry)):
                self._pending.discard(chash)

    def enforce_cap(self) -> int:
        """Evict least-recently-used shards exceeding the cap. Returns count evicted.

        Globs the shard dir and unlinks the oldest by mtime — the entry-count cap
        (byte-budget is a deferred follow-up). Bounded by the identity subdir.
        """
        try:
            shards = list(self._shard_dir.glob("*.json"))
        except OSError:
            return 0
        if len(shards) <= _MAX_CACHE_ENTRIES:
            return 0

        def _mtime(p: Path) -> float:
            try:
                return p.stat().st_mtime
            except OSError:
                return 0.0

        shards.sort(key=_mtime)
        to_evict = len(shards) - _MAX_CACHE_ENTRIES
        evicted = 0
        for p in shards[:to_evict]:
            with contextlib.suppress(OSError):
                p.unlink()
                evicted += 1
        return evicted

    def description_embedding(self, path: Path) -> tuple[int, ...] | None:
        """The description embedding stored with `path`'s per-file entry, or None."""
        try:
            entry = self.get(cache_key_for_path(path))
        except OSError:
            return None
        if entry is None or entry.description_embedding is None:
            return None
        return tuple(entry.description_embedding)

    def store_description_embeddings(self, records: list[FileRecord]) -> None:
        """Write each record's description embedding into its file's per-file entry."""
        for record in records:
            if record.description_embedding is None:
                continue
            try:
                key = cache_key_for_path(Path(record.path))
            except OSError:
                continue
            entry = self.get(key)
            if entry is not None:
                entry.description_embedding = list(record.description_embedding)
                self.put(key, entry)

    @property
    def size(self) -> int:
        """Number of cached shards in this cache's identity subdir."""
        try:
            return sum(1 for _ in self._shard_dir.glob("*.json"))
        except OSError:
            return 0


def _used_since(folder: Path, cutoff: float) -> bool:
    """True when the folder or any shard in it was modified (written or read) after `cutoff`."""
    try:
        if folder.stat().st_mtime >= cutoff:
            return True
        return any(e.stat().st_mtime >= cutoff for e in os.scandir(folder))
    except OSError:
        return True  # unreadable: leave it alone


def _now_iso() -> str:
    """Current UTC time as compact ISO string."""
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime())


def _as_offset(v: Any) -> tuple[int, int] | None:
    """JSON round-trips a tuple offset as a 2-element list; restore the tuple."""
    return tuple(v) if v is not None else None


def atoms_to_dicts(atoms: list[Atom]) -> list[dict[str, Any]]:
    """Serialize atoms to dicts for cache storage."""
    result = []
    for a in atoms:
        d = a.model_dump()
        # Convert tuple fields to lists for JSON
        if d.get("embedding_int8") is not None:
            d["embedding_int8"] = list(d["embedding_int8"])
        if d.get("topics"):
            d["topics"] = list(d["topics"])
        # `slots` text (subject/predicate/object/scope strings) is never cached. The
        # coordinate half (token offsets + per-span confidence) DOES survive, under
        # `slot_coords`, so a cache hit still carries the spans.
        # Written whenever the atom carries an `AtomSlots` at all — including an
        # all-None one — so a fresh atom with `slots=AtomSlots()` (no spans found)
        # round-trips back to `AtomSlots()`, not `None`: gating on "any span set"
        # made the write and the read asymmetric for that all-None case.
        slots = d.pop("slots", None)
        if slots is not None:
            d["slot_coords"] = {f: slots[f] for f in _SLOT_COORD_FIELDS}
        result.append(d)
    return result


def dicts_to_atoms(dicts: list[dict[str, Any]]) -> list[Atom]:
    """Deserialize atom dicts back to Atom instances.

    Copies each source dict (dropping keys the current Atom no longer declares)
    so the reconstructed atom never aliases the cache entry's stored dict and a
    stale-shape entry from a prior CLI version rehydrates instead of raising.
    """
    atoms = []
    for src in dicts:
        d = {k: v for k, v in src.items() if k in _ATOM_FIELD_NAMES}
        # Convert lists back to tuples
        if d.get("embedding_int8") is not None:
            d["embedding_int8"] = tuple(d["embedding_int8"])
        if d.get("topics") is not None:
            d["topics"] = tuple(d["topics"])
        # slots TEXT is never persisted (see atoms_to_dicts); drop a stale/raw
        # `slots` dict from a prior CLI version rather than pass it through as-is.
        d.pop("slots", None)
        slot_coords = src.get("slot_coords")
        if slot_coords:
            d["slots"] = AtomSlots(
                subject_span=_as_offset(slot_coords.get("subject_span")),
                predicate_span=_as_offset(slot_coords.get("predicate_span")),
                object_span=_as_offset(slot_coords.get("object_span")),
                scope_span=_as_offset(slot_coords.get("scope_span")),
                subject_conf=slot_coords.get("subject_conf", 0.0),
                predicate_conf=slot_coords.get("predicate_conf", 0.0),
                object_conf=slot_coords.get("object_conf", 0.0),
                scope_conf=slot_coords.get("scope_conf", 0.0),
            )
        atoms.append(Atom(**d))
    return atoms
