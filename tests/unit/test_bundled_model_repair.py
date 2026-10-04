"""Behavioral tests for `bundled.reload_after_repair`.

`reload_after_repair` wraps every bundled-model load (the sentence embedder,
the two bio-tagger encoders and heads). It must repair the persistent cache
only when the cache itself is provably damaged — a pinned file missing or
failing its sha256 — never for an unrelated load failure such as an
incompatible ONNX Runtime, a missing dependency, or an out-of-memory kill.
Concurrent failures share one repair: a second thread
that fails on the very same damaged file waits for that one repair and
retries its own load, instead of racing a second repair or giving up on a
failure that was fixable; every failure is judged on its own cache state, so
damage that appears later is still repaired.
"""

from __future__ import annotations

import threading
import time

import pytest

from reporails_cli import bundled
from reporails_cli.core.mapper import model_fetch


@pytest.fixture(autouse=True)
def _reset_repair_state(monkeypatch):
    """Every test starts with a clean per-process repair-coordination state.

    `tests/conftest.py` defaults `AILS_MODEL_OFFLINE=1` for the whole suite
    (never hit the network by accident); this module's own offline test sets
    it explicitly, every other test here is about the damaged/not-damaged
    decision and needs the online path.
    """
    monkeypatch.setattr(bundled, "_repair_events", {})
    monkeypatch.setattr(bundled, "_repair_generation", {})
    monkeypatch.setattr(bundled, "_known_sound", {}, raising=False)
    monkeypatch.setattr(bundled, "_known_unrepairable", {}, raising=False)
    monkeypatch.setattr(bundled, "_tree_present", False)
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_non_corruption_load_error_is_never_repaired(monkeypatch):
    """An ImportError, a MemoryError, an unsupported-opset failure, or any
    other load error that is not cache damage must surface unchanged — no
    download, no swap, and the cache is never touched to "fix" it."""
    checked = {"called": False}
    monkeypatch.setattr(model_fetch, "cache_damaged", lambda *a, **k: checked.update(called=True) or False)
    repaired = {"called": False}
    monkeypatch.setattr(model_fetch, "repair_cache", lambda *a, **k: repaired.update(called=True))

    def load():
        raise ImportError("onnxruntime is not installed in this environment")

    with pytest.raises(ImportError, match="onnxruntime is not installed"):
        bundled.reload_after_repair(load)

    assert checked["called"] is True  # the cache WAS checked directly...
    assert repaired["called"] is False  # ...and found not to be the cause, so no repair ran


@pytest.mark.unit
@pytest.mark.subsys_map
def test_offline_surfaces_the_real_error_not_damaged(monkeypatch):
    """With `AILS_MODEL_OFFLINE=1`, a load failure — even one that would
    otherwise be repairable — surfaces as the original error, not a repair
    attempt or a generic "damaged" message; there is nothing to repair with."""
    monkeypatch.setenv("AILS_MODEL_OFFLINE", "1")
    checked = {"called": False}
    monkeypatch.setattr(model_fetch, "cache_damaged", lambda *a, **k: checked.update(called=True) or True)
    repaired = {"called": False}
    monkeypatch.setattr(model_fetch, "repair_cache", lambda *a, **k: repaired.update(called=True))

    def load():
        raise RuntimeError("the real underlying error")

    with pytest.raises(RuntimeError, match="the real underlying error"):
        bundled.reload_after_repair(load)

    assert repaired["called"] is False
    assert checked["called"] is False  # short-circuited on offline before even checking


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_damaged_cache_is_repaired_once_then_the_retry_loads(monkeypatch):
    monkeypatch.setattr(model_fetch, "cache_damaged", lambda *a, **k: True)
    repaired = {"n": 0}
    monkeypatch.setattr(model_fetch, "repair_cache", lambda *a, **k: repaired.update(n=repaired["n"] + 1))

    calls = {"n": 0}

    def load():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("same-size corrupted ONNX load")
        return "loaded"

    assert bundled.reload_after_repair(load) == "loaded"
    assert repaired["n"] == 1
    assert calls["n"] == 2


@pytest.mark.unit
@pytest.mark.subsys_map
def test_damage_that_appears_after_a_non_damage_failure_is_still_repaired(monkeypatch):
    """A long-running process first fails a load for a reason that is not cache damage
    (out of memory); later a file is damaged. The later failure must be repaired."""
    state = {"damaged": False}
    monkeypatch.setattr(model_fetch, "cache_damaged", lambda *a, **k: state["damaged"])
    repaired = {"n": 0}

    def fake_repair(*a, **k):
        repaired["n"] += 1
        state["damaged"] = False

    monkeypatch.setattr(model_fetch, "repair_cache", fake_repair)

    def oom():
        raise MemoryError("out of memory")

    with pytest.raises(MemoryError):
        bundled.reload_after_repair(oom)
    assert repaired["n"] == 0

    state["damaged"] = True
    calls = {"n": 0}

    def load():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("corrupted")
        return "loaded"

    assert bundled.reload_after_repair(load) == "loaded"
    assert repaired["n"] == 1


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_repair_that_fails_midway_does_not_make_a_later_caller_retry_unrepaired(monkeypatch):
    """A repair download that raises must not be remembered as done: once the cache
    changes, the next failing load checks it again and repairs it."""
    attempts = {"n": 0}

    def flaky_repair(*a, **k):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise OSError("download interrupted")

    monkeypatch.setattr(model_fetch, "cache_damaged", lambda *a, **k: attempts["n"] < 2)
    monkeypatch.setattr(model_fetch, "repair_cache", flaky_repair)
    # the interrupted download leaves the cache files different from before
    monkeypatch.setattr(bundled, "_cache_fingerprint", lambda *a, **k: (("weights.bin", attempts["n"], 0),))

    def bad():
        raise RuntimeError("corrupted")

    with pytest.raises(OSError, match="download interrupted"):
        bundled.reload_after_repair(bad)

    calls = {"n": 0}

    def load():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("corrupted")
        return "loaded"

    assert bundled.reload_after_repair(load) == "loaded"
    assert attempts["n"] == 2


@pytest.mark.unit
@pytest.mark.subsys_map
def test_two_threads_failing_on_the_same_damaged_file_neither_raises(monkeypatch):
    """REGRESSION: a real two-thread race. Both threads' first load fails on
    the same damaged file; one repairs, the other waits for that repair and
    retries its own load — neither gets an exception from the coordination
    itself (the shape of the FileNotFoundError this used to produce), and the
    repair runs exactly once."""
    repair_started = threading.Event()
    release_repair = threading.Event()
    fixed = threading.Event()
    repaired = {"n": 0}

    def fake_repair(*a, **k):
        repair_started.set()
        release_repair.wait(timeout=5)
        repaired["n"] += 1
        fixed.set()

    monkeypatch.setattr(model_fetch, "cache_damaged", lambda *a, **k: True)
    monkeypatch.setattr(model_fetch, "repair_cache", fake_repair)

    def load():
        if not fixed.is_set():
            raise RuntimeError("same corrupted file")
        return "loaded"

    results: list[object] = []
    errors: list[BaseException] = []

    def run():
        try:
            results.append(bundled.reload_after_repair(load))
        except BaseException as exc:
            errors.append(exc)

    t1 = threading.Thread(target=run)
    t2 = threading.Thread(target=run)
    t1.start()
    assert repair_started.wait(timeout=5)  # t1 is the leader, inside the (fake) repair
    t2.start()
    time.sleep(0.2)  # give t2 a real chance to queue behind t1's repair as the follower
    release_repair.set()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert errors == []
    assert sorted(results) == ["loaded", "loaded"]
    assert repaired["n"] == 1


@pytest.fixture
def real_cache(monkeypatch, tmp_path):
    """A one-file model cache on disk with a real pin, and a counter of full-file hashes."""
    import hashlib

    root = tmp_path / "models"
    root.mkdir()
    weights = root / "weights.bin"
    weights.write_bytes(b"good weights")
    monkeypatch.setattr(model_fetch, "cache_models_dir", lambda version=model_fetch.MODEL_VERSION: root)
    monkeypatch.setattr(model_fetch, "REQUIRED_RELPATHS", ("weights.bin",))
    monkeypatch.setattr(model_fetch, "FETCH_SHA256", {"weights.bin": hashlib.sha256(b"good weights").hexdigest()})
    hashed = {"n": 0}
    real_sha = model_fetch._file_sha256

    def counting(path):
        hashed["n"] += 1
        return real_sha(path)

    monkeypatch.setattr(model_fetch, "_file_sha256", counting)
    return weights, hashed


def _fails(message="onnxruntime refused the model"):
    def load():
        raise RuntimeError(message)

    return load


@pytest.mark.unit
@pytest.mark.subsys_map
def test_repeated_load_failures_over_unchanged_sound_files_hash_the_model_once(monkeypatch, real_cache):
    """A long-running server whose load keeps failing for a reason outside the files
    verifies them once; later failures over the same files do not hash them again."""
    _weights, hashed = real_cache
    repaired = {"n": 0}
    monkeypatch.setattr(model_fetch, "repair_cache", lambda *a, **k: repaired.update(n=repaired["n"] + 1))

    for _ in range(3):
        with pytest.raises(RuntimeError, match="refused the model"):
            bundled.reload_after_repair(_fails())

    assert hashed["n"] == 1
    assert repaired["n"] == 0


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_file_damaged_after_a_sound_verdict_is_verified_and_repaired(monkeypatch, real_cache):
    import os

    weights, hashed = real_cache
    repaired = {"n": 0}

    def fix(*a, **k):
        repaired["n"] += 1
        weights.write_bytes(b"good weights")

    monkeypatch.setattr(model_fetch, "repair_cache", fix)
    with pytest.raises(RuntimeError):
        bundled.reload_after_repair(_fails())
    assert hashed["n"] == 1

    stat = weights.stat()
    weights.write_bytes(b"bad  weights")  # same size, different bytes
    os.utime(weights, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))

    calls = {"n": 0}

    def load():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("corrupted")
        return "loaded"

    assert bundled.reload_after_repair(load) == "loaded"
    assert hashed["n"] >= 2
    assert repaired["n"] == 1


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_failed_repair_is_not_tried_again_while_the_files_are_unchanged(monkeypatch, real_cache):
    import os

    weights, hashed = real_cache
    stat = weights.stat()
    weights.write_bytes(b"bad  weights")
    os.utime(weights, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))
    attempts = {"n": 0}

    def offline_download(*a, **k):
        attempts["n"] += 1
        raise model_fetch.ModelFetchError("could not repair the model cache: no network")

    monkeypatch.setattr(model_fetch, "repair_cache", offline_download)

    for _ in range(3):
        with pytest.raises(model_fetch.ModelFetchError, match="no network"):
            bundled.reload_after_repair(_fails("corrupted"))

    assert attempts["n"] == 1
    assert hashed["n"] == 1

    weights.write_bytes(b"other bytes!")  # the file changes: the repair is tried again
    with pytest.raises(model_fetch.ModelFetchError):
        bundled.reload_after_repair(_fails("corrupted"))
    assert attempts["n"] == 2


class _Clock:
    """A movable stand-in for the monotonic clock the repair memo reads."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    fake = _Clock()
    monkeypatch.setattr(bundled, "time", fake, raising=False)
    return fake


def _damage(weights):
    import os

    stat = weights.stat()
    weights.write_bytes(b"bad  weights")
    os.utime(weights, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_failed_repair_is_tried_again_after_the_wait_and_the_load_retried(monkeypatch, real_cache, clock):
    weights, hashed = real_cache
    _damage(weights)
    attempts = {"n": 0}

    def repair(*a, **k):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise model_fetch.ModelFetchError("could not repair the model cache: no network")
        weights.write_bytes(b"good weights")

    monkeypatch.setattr(model_fetch, "repair_cache", repair)
    with pytest.raises(model_fetch.ModelFetchError, match="no network"):
        bundled.reload_after_repair(_fails("corrupted"))

    clock.now += bundled.REPAIR_RETRY_WAIT_SECONDS - 1
    hashes_before = hashed["n"]
    with pytest.raises(model_fetch.ModelFetchError, match="no network"):
        bundled.reload_after_repair(_fails("corrupted"))
    assert attempts["n"] == 1
    assert hashed["n"] == hashes_before

    clock.now += 2  # the wait has now passed
    calls = {"n": 0}

    def load():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("corrupted")
        return "loaded"

    assert bundled.reload_after_repair(load) == "loaded"
    assert attempts["n"] == 2
    assert calls["n"] == 2


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_repair_that_fails_again_after_the_wait_restarts_the_wait(monkeypatch, real_cache, clock):
    weights, _hashed = real_cache
    _damage(weights)
    attempts = {"n": 0}

    def offline_download(*a, **k):
        attempts["n"] += 1
        raise model_fetch.ModelFetchError("could not repair the model cache: no network")

    monkeypatch.setattr(model_fetch, "repair_cache", offline_download)
    wait = bundled.REPAIR_RETRY_WAIT_SECONDS

    with pytest.raises(model_fetch.ModelFetchError):
        bundled.reload_after_repair(_fails("corrupted"))
    clock.now += wait + 1
    with pytest.raises(model_fetch.ModelFetchError):
        bundled.reload_after_repair(_fails("corrupted"))
    assert attempts["n"] == 2

    clock.now += wait - 1  # inside the restarted wait
    with pytest.raises(model_fetch.ModelFetchError):
        bundled.reload_after_repair(_fails("corrupted"))
    assert attempts["n"] == 2

    clock.now += 2
    with pytest.raises(model_fetch.ModelFetchError):
        bundled.reload_after_repair(_fails("corrupted"))
    assert attempts["n"] == 3


@pytest.mark.unit
@pytest.mark.subsys_map
def test_sound_files_are_never_hashed_again_however_much_time_passes(monkeypatch, real_cache, clock):
    _weights, hashed = real_cache
    monkeypatch.setattr(model_fetch, "repair_cache", lambda *a, **k: pytest.fail("repair attempted"))

    with pytest.raises(RuntimeError):
        bundled.reload_after_repair(_fails())
    clock.now += bundled.REPAIR_RETRY_WAIT_SECONDS * 100
    with pytest.raises(RuntimeError):
        bundled.reload_after_repair(_fails())

    assert hashed["n"] == 1
