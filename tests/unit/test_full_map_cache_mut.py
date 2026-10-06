"""Mutation-killing behavioral tests for core/cache/full_map_cache.py survivors.

Only the `put` mkdir flags carry an observable contract. The other survivors are
equivalent mutants and are documented rather than decorated:

  - L89 / L103 `logger.debug(..., exc_info=True)`: `True -> False` only changes
    whether a traceback is attached to a debug log line; the `return None` /
    early-return behavior is unchanged — cosmetic logging param, equivalent.
  - L111 `stale.unlink(missing_ok=True)`: `True -> False` matters only if the
    globbed entry vanishes between the glob and the unlink (a concurrent
    delete). In a single-threaded run every globbed file still exists at unlink
    time, so the guard never decides — equivalent.

The real contract: `self.dir.mkdir(parents=True, exist_ok=True)` inside a
try/except OSError. Flipping either flag turns a normal put into a caught
OSError that silently drops the write, so the map never becomes retrievable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.cache.full_map_cache import FullMapCache


def _make_map():
    from reporails_cli.core.platform.dto.ruleset import (
        EMBEDDING_MODEL,
        SCHEMA_VERSION,
        Atom,
        FileRecord,
        RulesetMap,
        RulesetSummary,
    )

    atom = Atom(
        line=1,
        text="use x",
        kind="excitation",
        charge="DIRECTIVE",
        charge_value=1,
        modality="imperative",
        specificity="named",
    )
    return RulesetMap(
        schema_version=SCHEMA_VERSION,
        embedding_model=EMBEDDING_MODEL,
        generated_at="2026-07-06T00:00:00Z",
        files=(FileRecord(path="a.md", content_hash="sha256:abc"),),
        atoms=(atom,),
        summary=RulesetSummary(n_atoms=1, n_charged=1, n_neutral=0),
    )


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_put_into_preexisting_cache_dir_persists(tmp_path: Path) -> None:
    cache = FullMapCache(tmp_path)
    cache.dir.mkdir(parents=True)  # dir already exists before the first put
    cache.put("k1", _make_map())
    # `exist_ok=True -> False`: mkdir on an existing dir raises FileExistsError,
    # caught as OSError, so the write is silently dropped and get() misses.
    assert cache.get("k1") is not None


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_put_creates_missing_intermediate_dirs(tmp_path: Path) -> None:
    cache = FullMapCache(tmp_path / "x" / "y")  # intermediate "y" does not exist
    cache.put("k1", _make_map())
    # `parents=True -> False`: mkdir cannot create the missing parent, raises
    # FileNotFoundError, caught as OSError, so the write is silently dropped.
    assert cache.get("k1") is not None


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_put_survives_an_entry_another_writer_evicted_mid_sweep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent writers each `put` and sweep the same cache dir: an entry the sweep listed can
    be gone (another writer evicted it) before this sweep stats it. The put must still land and
    return, never fail the caller with a vanished-file error."""
    cache = FullMapCache(tmp_path)
    cache.dir.mkdir(parents=True)
    vanished = cache.dir / "gone.json"
    real_glob = Path.glob

    def glob_with_vanished(self: Path, pattern: str):  # type: ignore[no-untyped-def]
        yield from real_glob(self, pattern)
        if self == cache.dir:
            yield vanished

    monkeypatch.setattr(Path, "glob", glob_with_vanished)
    cache.put("k1", _make_map())
    assert cache.get("k1") is not None
