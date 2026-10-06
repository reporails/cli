"""Behavioral tests for core/cache/map_cache.py — the per-content-hash shard store.

The cache stores one small JSON file per content hash under a per-identity subdir
(`<cache_dir>/map-atoms/<identity-digest>/<hash>.json`), so a run reads only the
shards for the files it maps rather than a whole-corpus blob. These tests cover the
shard round-trip, the one-shot migration off the legacy `map-cache.json` monolith,
mtime-LRU eviction, corrupt-shard tolerance, identity-digest separation, and the
concurrent-write race the atomic per-shard write must not reintroduce.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import os
import time
from pathlib import Path

import pytest

from reporails_cli.core.cache.map_cache import (
    _CACHE_VERSION,
    CachedFileEntry,
    MapCache,
)
from reporails_cli.core.platform.dto.ruleset import EMBEDDING_MODEL, SCHEMA_VERSION


def _shard_dir(cache: MapCache) -> Path:
    return cache._shard_dir


def _concurrent_put_worker(cache_dir_str: str, idx: int, barrier: mp.synchronize.Barrier, rounds: int) -> None:
    """Each round: put a unique entry, then rendezvous so writes land together.

    The failure mode this guards is a race between concurrent shard writes; each
    shard is written to its own `mkstemp` name and `os.replace`d, so unique hashes
    never share a source path.
    """
    cache_dir = Path(cache_dir_str)
    for r in range(rounds):
        cache = MapCache(cache_dir)
        cache.load()
        cache.put(f"sha256:worker{idx}-{r}", CachedFileEntry(content_hash=f"sha256:worker{idx}-{r}"))
        barrier.wait()
        cache.save()


# --- shard round-trip -----------------------------------------------------
@pytest.mark.unit
@pytest.mark.subsys_caching
def test_put_writes_a_shard_and_get_reads_it_across_instances(tmp_path: Path) -> None:
    writer = MapCache(tmp_path)
    writer.put("sha256:abc", CachedFileEntry(content_hash="sha256:abc", atoms=[{"text": "x"}]))

    # A fresh instance (no shared memory) reads the shard off disk.
    reader = MapCache(tmp_path)
    reader.load()
    entry = reader.get("sha256:abc")
    assert entry is not None
    assert entry.atoms == [{"text": "x"}]
    # One file per entry, under the per-identity subdir — not a single blob.
    shards = list(_shard_dir(reader).glob("*.json"))
    assert len(shards) == 1


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_get_miss_returns_none(tmp_path: Path) -> None:
    cache = MapCache(tmp_path)
    cache.load()
    assert cache.get("sha256:absent") is None


# --- fresh cache: save writes nothing -------------------------------------
@pytest.mark.unit
@pytest.mark.subsys_caching
def test_fresh_cache_save_is_noop(tmp_path: Path) -> None:
    cache = MapCache(tmp_path / "cache")
    cache.save()
    # Nothing put → no shard written, and the legacy monolith is never created.
    assert not (tmp_path / "cache" / "map-cache.json").exists()
    assert cache.size == 0


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_put_creates_missing_parent_dirs(tmp_path: Path) -> None:
    cache_dir = tmp_path / "a" / "b" / "c"  # parents do not exist yet
    cache = MapCache(cache_dir)
    cache.put("sha256:abc", CachedFileEntry(content_hash="sha256:abc"))
    # `mkdir(parents=True)` in the shard writer creates the whole chain.
    assert _shard_dir(cache).is_dir()
    assert cache.size == 1


# --- migration off the legacy monolith ------------------------------------
def _write_monolith(cache_dir: Path, *, entries: dict, model: str = EMBEDDING_MODEL) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "version": _CACHE_VERSION,
        "model": model,
        "schema": SCHEMA_VERSION,
        "segmentation": "legacy",
        "charge": "",
        "entries": entries,
    }
    (cache_dir / "map-cache.json").write_text(json.dumps(data), encoding="utf-8")


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_migration_matching_identity_preserves_entries_and_removes_monolith(tmp_path: Path) -> None:
    _write_monolith(
        tmp_path,
        entries={"sha256:warm": {"atoms": [{"text": "kept"}], "last_used": "20240101T000000"}},
    )
    cache = MapCache(tmp_path)  # default identity matches the monolith's
    cache.load()
    # The warm entry survived the split into a shard ...
    entry = cache.get("sha256:warm")
    assert entry is not None
    assert entry.atoms == [{"text": "kept"}]
    # ... and the monolith is gone.
    assert not (tmp_path / "map-cache.json").exists()


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_migration_identity_mismatch_removes_monolith_and_serves_nothing(tmp_path: Path) -> None:
    _write_monolith(
        tmp_path,
        entries={"sha256:stale": {"atoms": [{"text": "old"}], "last_used": "20240101T000000"}},
        model="some-other-model",  # identity mismatch
    )
    cache = MapCache(tmp_path)
    cache.load()
    assert cache.get("sha256:stale") is None
    assert cache.size == 0
    assert not (tmp_path / "map-cache.json").exists()


# --- corrupt shard is tolerated -------------------------------------------
@pytest.mark.unit
@pytest.mark.subsys_caching
def test_corrupt_shard_returns_none_without_raising(tmp_path: Path) -> None:
    cache = MapCache(tmp_path)
    cache.put("sha256:abc", CachedFileEntry(content_hash="sha256:abc", atoms=[{"text": "x"}]))
    # Corrupt the shard on disk, then read from a fresh instance.
    shard = next(_shard_dir(cache).glob("*.json"))
    shard.write_text("{ not valid json", encoding="utf-8")
    reader = MapCache(tmp_path)
    reader.load()
    assert reader.get("sha256:abc") is None  # tolerated, run continues


# --- identity-digest separation -------------------------------------------
@pytest.mark.unit
@pytest.mark.subsys_caching
def test_identity_change_lands_in_a_fresh_digest_dir(tmp_path: Path) -> None:
    a = MapCache(tmp_path, charge="111:222")
    a.put("sha256:abc", CachedFileEntry(content_hash="sha256:abc", atoms=[{"text": "x"}]))
    # A different charge fingerprint is a different digest subdir → no cross-serve.
    b = MapCache(tmp_path, charge="111:999")
    b.load()
    assert b.get("sha256:abc") is None
    assert _shard_dir(a) != _shard_dir(b)


# --- enforce_cap: mtime-LRU over shard files ------------------------------
@pytest.mark.unit
@pytest.mark.subsys_caching
def test_enforce_cap_at_exact_cap_evicts_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("reporails_cli.core.cache.map_cache._MAX_CACHE_ENTRIES", 2)
    cache = MapCache(tmp_path)
    cache.put("a", CachedFileEntry(content_hash="a"))
    cache.put("b", CachedFileEntry(content_hash="b"))
    # `<=`->`<` would fall through the guard at exactly the cap and evict one.
    assert cache.enforce_cap() == 0
    assert cache.size == 2


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_enforce_cap_evicts_oldest_by_mtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("reporails_cli.core.cache.map_cache._MAX_CACHE_ENTRIES", 2)
    cache = MapCache(tmp_path)
    for h in ("a", "b", "c", "d"):
        cache.put(h, CachedFileEntry(content_hash=h))
    # Force a strict mtime order: a oldest ... d newest.
    shard_dir = _shard_dir(cache)
    for i, h in enumerate(("a", "b", "c", "d")):
        os.utime(shard_dir / f"{h}.json", (1_000_000 + i, 1_000_000 + i))
    evicted = cache.enforce_cap()
    assert evicted == 2
    survivors = {p.stem for p in shard_dir.glob("*.json")}
    # The two newest survive; the two oldest were evicted.
    assert survivors == {"c", "d"}


# --- save: no-op when nothing is pending ----------------------------------
@pytest.mark.unit
@pytest.mark.subsys_caching
def test_save_after_successful_puts_does_not_raise(tmp_path: Path) -> None:
    cache = MapCache(tmp_path)
    cache.put("sha256:abc", CachedFileEntry(content_hash="sha256:abc"))
    # Shards are written eagerly at put(); save() has no pending writes to retry.
    cache.save()
    assert cache.size == 1


# --- concurrent shard writes from multiple processes ----------------------
@pytest.mark.unit
@pytest.mark.subsys_caching
def test_concurrent_puts_from_multiple_processes_do_not_raise(tmp_path: Path) -> None:
    """4 processes hammering put()+save() against one cache dir must never raise.

    Each shard is written to its own `mkstemp` name and `os.replace`d atomically,
    so distinct hashes never share a source path and no `FileNotFoundError` races
    out of a shared tmp name (the monolith's failure mode).
    """
    n_procs = 4
    rounds = 25
    barrier = mp.Barrier(n_procs)
    procs = [
        mp.Process(target=_concurrent_put_worker, args=(str(tmp_path), i, barrier, rounds)) for i in range(n_procs)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)

    assert all(p.exitcode == 0 for p in procs), [p.exitcode for p in procs]

    reader = MapCache(tmp_path)
    reader.load()
    assert reader.size == n_procs * rounds
    assert not list(_shard_dir(reader).glob(".shard-*.tmp")), "a leftover tmp file means a shard write did not clean up"


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_load_prunes_identity_subdirs_unused_for_a_long_time(tmp_path: Path) -> None:
    """A sibling identity subdir that no run has read or written for a long time
    is removed on `load()`, bounding the disk a retired configuration leaves."""
    cache = MapCache(tmp_path)
    stale = tmp_path / "map-atoms" / "deadbeefdeadbeef"
    stale.mkdir(parents=True)
    shard = stale / "old.json"
    shard.write_text("{}", encoding="utf-8")
    long_ago = time.time() - 60 * 86400
    os.utime(shard, (long_ago, long_ago))
    os.utime(stale, (long_ago, long_ago))
    cache.put("sha256:live", CachedFileEntry("sha256:live", [{"a": 1}]))
    assert stale.exists()

    cache.load()

    assert not stale.exists(), "long-unused identity subdir was not pruned"
    reader = MapCache(tmp_path)
    reader.load()
    assert reader.get("sha256:live") is not None, "current-identity shard must survive the prune"


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_load_keeps_another_configurations_warm_cache(tmp_path: Path) -> None:
    """Opening a cache under one segmentation leaves the shards of a project
    that uses another segmentation in place."""
    first = MapCache(tmp_path, segmentation="structure-aware")
    first.load()
    first.put("sha256:a", CachedFileEntry("sha256:a", [{"a": 1}]))

    second = MapCache(tmp_path, segmentation="legacy")
    second.load()
    second.put("sha256:b", CachedFileEntry("sha256:b", [{"b": 1}]))
    second.load()

    again = MapCache(tmp_path, segmentation="structure-aware")
    again.load()
    assert again.get("sha256:a") is not None, "the other configuration's warm shard was removed"
    assert len(list((tmp_path / "map-atoms").iterdir())) == 2


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_migration_keeps_monolith_when_a_shard_write_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A failed shard write mid-migration must NOT delete the warm monolith —
    the next run retries instead of dropping to a cold rebuild."""
    cache = MapCache(tmp_path)
    _write_monolith(tmp_path, entries={"sha256:a": {"atoms": [], "last_used": ""}})
    monkeypatch.setattr(cache, "_write_shard", lambda *a, **k: False)

    cache.load()

    assert cache.cache_path.exists(), "monolith removed despite a failed shard write — warm cache lost"


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_migration_removes_monolith_on_clean_split(tmp_path: Path) -> None:
    """A clean identity-matched migration splits entries to shards then removes the monolith."""
    cache = MapCache(tmp_path)
    _write_monolith(tmp_path, entries={"sha256:a": {"atoms": [{"x": 1}], "last_used": ""}})

    cache.load()

    assert not cache.cache_path.exists(), "monolith not removed after a clean migration"
    reader = MapCache(tmp_path)
    reader.load()
    assert reader.get("sha256:a") is not None, "migrated entry not served from its shard"
