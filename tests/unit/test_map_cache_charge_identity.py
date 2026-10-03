"""The map cache keys on the charge-head fingerprint, so a head swap
invalidates cached charges instead of serving stale ones."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.cache.map_cache import CachedFileEntry, MapCache


def _seed(cache_dir: Path, charge: str) -> None:
    cache = MapCache(cache_dir, charge=charge)
    cache.put("sha256:abc", CachedFileEntry(content_hash="sha256:abc", atoms=[{"text": "x"}]))
    cache.save()


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_same_charge_fingerprint_warm_hit(tmp_path: Path) -> None:
    _seed(tmp_path, "111:222")
    cache = MapCache(tmp_path, charge="111:222")
    cache.load()
    assert cache.get("sha256:abc") is not None
    assert cache.size == 1


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_changed_charge_fingerprint_invalidates(tmp_path: Path) -> None:
    # Head swap: same graph, new mtime/size -> new fingerprint.
    _seed(tmp_path, "111:222")
    cache = MapCache(tmp_path, charge="111:999")
    cache.load()
    assert cache.get("sha256:abc") is None
    assert cache.size == 0


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_default_charge_token_round_trips(tmp_path: Path) -> None:
    # A cache written under the default charge token round-trips under that default.
    _seed(tmp_path, "")
    cache = MapCache(tmp_path)
    cache.load()
    assert cache.size == 1


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_whole_map_identity_folds_charge_head_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    # REGRESSION: the whole-map identity must fold multislot_fingerprint(), so a
    # charge-head re-export (new fingerprint, unchanged atom shape) MISSES the cached map
    # instead of serving stale charges. The per-file cache already did this; the whole-map
    # short-circuit did not.
    import reporails_cli.core.mapper.bio_tagger as bt
    from reporails_cli.core.cache.full_map_cache import compute_identity

    paths = [Path("a.md")]
    root = Path(".")
    monkeypatch.setattr(bt, "multislot_fingerprint", lambda: "AAA")
    k_a = compute_identity(paths, root=root)
    k_a2 = compute_identity(paths, root=root)
    monkeypatch.setattr(bt, "multislot_fingerprint", lambda: "BBB")
    k_b = compute_identity(paths, root=root)
    assert k_a == k_a2  # same fingerprint → same identity
    assert k_a != k_b  # head swap → different identity → cache miss
