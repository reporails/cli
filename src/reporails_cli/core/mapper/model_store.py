"""How the model set is made available on disk, and repair of a damaged cache.

Where the set lives is ``model_manifest.get_models_path``; ``model_fetch`` fills the
persistent user cache once on first use.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from reporails_cli.core.mapper import model_fetch, model_manifest
from reporails_cli.core.mapper.graph_hash import graph_content_hash


@dataclass
class _RepairFlight:
    """One repair attempt in progress; `retry` says whether callers should reload."""

    done: threading.Event = field(default_factory=threading.Event)
    retry: bool = False


# `reload_after_repair` coordination: threads failing on the same damaged file at
# the same moment share one repair (the first is the leader, the rest wait for it
# and retry their own load). A file that changes after an attempt is verified afresh,
# so damage that appears later in a long-running process is repaired when it appears.
_repair_lock = threading.Lock()
_repair_events: dict[str, _RepairFlight] = {}
# What a failed load taught about the cache, per model version, keyed by the cache
# fingerprint (size and modification time of every required file): `_known_sound`
# holds the fingerprint at which every file verified, `_known_unrepairable` the
# fingerprint at which a repair was tried and failed, with its message and the time
# it failed. A later failure over the same fingerprint reuses a sound verdict
# instead of hashing the model again, and a failed repair for the length of the
# wait below; any file that changes gets verified afresh.
_Fingerprint = tuple[tuple[str, int, int] | None, ...]
_known_sound: dict[str, _Fingerprint] = {}
# Seconds a failed repair is remembered before the next failure tries it again.
REPAIR_RETRY_WAIT_SECONDS = 60.0
_known_unrepairable: dict[str, tuple[_Fingerprint, str, float]] = {}
# Completed successful repairs per model version: a caller whose load began before
# one finished retries without repairing again.
_repair_generation: dict[str, int] = {}


def ensure_models_available() -> Path | None:
    """Make the model set available on disk, downloading it once if needed.

    Returns the model directory, or ``None`` when ``AILS_MODEL_OFFLINE`` is set
    and no set is on disk (the caller runs without the model and says so).
    Raises ``ModelFetchError`` when the download fails.
    """
    path = model_manifest.get_models_path()
    if model_manifest.models_present(path):
        if not model_manifest.in_package_tree_present():
            _repair_if_damaged(path)
        return path
    if model_fetch.offline_requested():
        return None
    return model_fetch.ensure_models_present(model_manifest.MODEL_VERSION)


def _repair_if_damaged(root: Path) -> None:
    """Re-fetch any file of the cached set whose content differs from its pinned digest.

    A file damaged in place keeps its size, so the presence check passes, and it may
    still load. Each file's digest is memoized on disk by size and modification time (the
    same record the cache identity uses), so an unchanged set costs no re-hash on a normal
    run. Raises ``ModelFetchError`` when the set is damaged and cannot be repaired.
    """
    if all(
        graph_content_hash(root / rel) == model_manifest.FETCH_SHA256[rel] for rel in model_manifest.REQUIRED_RELPATHS
    ):
        return
    model_fetch.repair_cache(model_manifest.MODEL_VERSION)


def reload_after_repair[T](load: Callable[[], T]) -> T:
    """Call *load*; on failure, repair the persistent model cache if damaged and retry.

    A cached model file corrupted in place (disk error, a sync or backup tool,
    an AV rewrite) keeps its size, so the presence check that gates a download
    passes, but the loader fails on the bad bytes. Repair is attempted only when
    the cache is provably damaged — a pinned file missing or failing its sha256,
    checked directly against the files on disk — never guessed from the
    exception. Any other load failure (an incompatible runtime, a missing
    dependency, an out-of-memory kill, or any failure while ``AILS_MODEL_OFFLINE``
    is set, since there is nothing to repair with) surfaces unchanged: no
    download, no swap.

    Threads that fail on the same damaged file together share one repair: the
    first repairs, the others wait for it and retry their own *load*. Every
    failure is judged on its own cache state, so a file damaged later in a
    long-running process is still repaired then.

    Never repairs the in-package dev tree (no pins apply there — see
    ``model_manifest.get_models_path``); that failure re-raises unchanged, since a network
    repair could not fix it anyway.
    """
    version = model_manifest.MODEL_VERSION
    seen = _repair_generation.get(version, 0)
    try:
        return load()
    except Exception:  # pylint: disable=broad-exception-caught  # native loaders raise bare Exception; re-raised unless the cache is damaged
        if model_manifest.in_package_tree_present():
            raise
        if _repair_generation.get(version, 0) != seen:
            return load()  # another thread finished a repair while this load was failing
        if not _repair_once(version):
            raise
        return load()


def _repair_once(version: str) -> bool:
    """Repair *version*'s persistent cache if it is damaged; share one attempt across concurrent callers.

    Returns whether the caller should retry its ``load()``: true only when the
    cache was damaged and the repair completed. A repair that fails raises to
    the leader and tells every waiter not to retry.
    """
    with _repair_lock:
        flight = _repair_events.get(version)
        leader = flight is None
        if flight is None:
            flight = _repair_events[version] = _RepairFlight()

    if not leader:
        flight.done.wait()
        return flight.retry

    try:
        flight.retry = _verify_and_repair(version)
    finally:
        with _repair_lock:
            _repair_events.pop(version, None)
        flight.done.set()
    return flight.retry


def _cache_fingerprint(version: str) -> _Fingerprint:
    """Size and modification time of every required file of *version*'s cache.

    A missing file is ``None``. Two equal fingerprints mean no required file was
    replaced, truncated or rewritten between them, so a verdict reached for one holds
    for the other without hashing the files again."""
    root = model_manifest.cache_models_dir(version)
    out: list[tuple[str, int, int] | None] = []
    for rel in model_manifest.REQUIRED_RELPATHS:
        try:
            st = (root / rel).stat()
        except OSError:
            out.append(None)
            continue
        out.append((rel, st.st_size, st.st_mtime_ns))
    return tuple(out)


def _verify_and_repair(version: str) -> bool:
    """Verify *version*'s cache and repair it when damaged; whether the caller should retry.

    The verdict for a given cache fingerprint is remembered: a cache that verified
    sound is not hashed again while its files are unchanged, and a repair that failed
    is not tried again until a file changes or the short wait after the failure has passed.
    """
    if model_fetch.offline_requested():
        return False
    fingerprint = _cache_fingerprint(version)
    if _known_sound.get(version) == fingerprint:
        return False
    failed = _known_unrepairable.get(version)
    if failed is not None and failed[0] == fingerprint and time.monotonic() - failed[2] < REPAIR_RETRY_WAIT_SECONDS:
        raise model_manifest.ModelFetchError(failed[1])
    if not model_fetch.cache_damaged(version):
        if None not in fingerprint:
            _known_sound[version] = fingerprint
        return False
    try:
        model_fetch.repair_cache(version)
    except Exception as exc:
        _known_unrepairable[version] = (fingerprint, str(exc), time.monotonic())
        raise
    with _repair_lock:
        _repair_generation[version] = _repair_generation.get(version, 0) + 1
    _known_sound.pop(version, None)
    _known_unrepairable.pop(version, None)
    return True
