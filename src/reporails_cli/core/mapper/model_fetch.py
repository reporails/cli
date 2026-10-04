"""Runtime fetch of the model set into the persistent user cache.

End users install a lean wheel (code + rules, no weights). The model set is fetched once,
on first use, into ``~/.reporails/cache/models/<MODEL_VERSION>/`` — the persistent
user-home cache, **not** the ephemeral npx package cache. The download therefore happens
once per machine and survives every npx cold-cache miss (npx re-pulls only the lean
wheel). Cache hit on every later run is silent and offline.

The model version is independent of the CLI version: a CLI upgrade that keeps
``MODEL_VERSION`` reuses the cached set, and bumping it fetches into a fresh cache dir.

The download needs no account — from the default host, overridable to a
mirror via ``AILS_MODEL_URL`` without a code change. A signed-in user's API key goes to
the default host only, never to a mirror. Every functional file is verified against a
pinned sha256 before it enters the cache, so the host is trusted for availability only. A
first run with no reachable host raises a clear :class:`ModelFetchError` rather than
leaving a partial or HTML-interstitial artifact in the cache. ``AILS_MODEL_OFFLINE=1``
never downloads: only a model already on disk is used.
"""

from __future__ import annotations

import functools
import hashlib
import os
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

# ─── Version + host ───────────────────────────────────────────────────

# Model-set identity, independent of the CLI version. Bump to ship a new
# encoder set: the runtime fetches into a fresh cache dir. After a fetch the
# cache keeps the new set and the most recent other one (a downgrade by one
# model version still finds its cache); older sets are removed.
MODEL_VERSION = "m1"

# Default host: ``<base>/<asset>`` with the base below. Overridable to any
# flat-keyed host (a mirror or internal cache) via ``AILS_MODEL_URL``.
_DEFAULT_BASE = "https://models.reporails.com/{version}"
_ENV_URL = "AILS_MODEL_URL"

# Set to a truthy value to never download: only a model already on disk is used.
_ENV_OFFLINE = "AILS_MODEL_OFFLINE"

# Approximate total size of the fetched set, shown once in the first-run banner.
_APPROX_TOTAL_MB = 264

# Streamed download chunk size.
_CHUNK = 1 << 20

# A busy host (HTTP 429 / 503) is retried after its Retry-After, capped, up to
# this many attempts per file.
_RETRY_STATUSES = frozenset({429, 503})
_MAX_ATTEMPTS = 3
_MAX_RETRY_WAIT_S = 60

# Printed with the download banner in GitHub Actions, where every run starts
# from an empty home directory unless the model is cached between runs.
_CI_CACHE_HINT = (
    "Running in GitHub Actions: cache ~/.reporails/cache/models between runs so later runs "
    "skip this download (reporails/cli/action does this for you): "
    "https://github.com/reporails/cli/blob/main/docs/configuration.md#caching-the-model-in-ci"
)

# Staging dirs older than this were left by a run that died mid-download.
_STALE_STAGING_S = 6 * 3600

# ─── Manifest (single source of truth for WHAT ships) ─────────────────

# The embedder subtree, mirrored from the current ``bundled/models/`` layout. Only the
# model graph and the self-contained ``tokenizer.json`` are read at runtime; the other
# metadata files that sit beside them in the source layout are never read, so they are
# excluded from the fetch.
EMBEDDER_SUBDIR = "minilm-l6-v2"
EMBEDDER_FILES: tuple[str, ...] = (
    "onnx/model.onnx",
    "tokenizer.json",
)

# The classifier files, at the models root.
GATED_FILES: tuple[str, ...] = (
    "charge_encoder_encA.onnx",
    "charge_encoder_encB.onnx",
    "multislot_head_encA.onnx",
    "multislot_head_encB.onnx",
)

# The licence files travel with the model set: a file pulled from a user's cache carries its own
# grant (the model licence, the third-party notice and the Apache-2.0 text that notice refers to).
# The fetch is strict about them — a licence file the host cannot serve fails the whole fetch, so
# no weight reaches a cache without its grant. They are not part of the functional present-check
# below, because loading the model does not read them.
LICENSE_FILES: tuple[str, ...] = ("LICENSE-weights", "NOTICE", "LICENSE-APACHE-2.0")


def _required_relpaths() -> tuple[str, ...]:
    """Functional files that must all be present for the model to load."""
    return GATED_FILES + tuple(f"{EMBEDDER_SUBDIR}/{f}" for f in EMBEDDER_FILES)


# Everything the resolver requires (functional) vs. everything fetched.
REQUIRED_RELPATHS: tuple[str, ...] = _required_relpaths()
FETCH_RELPATHS: tuple[str, ...] = (*REQUIRED_RELPATHS, *LICENSE_FILES)

# Pinned sha256 of every functional file for ``MODEL_VERSION``. A download whose
# digest differs is rejected before it can enter the cache. Regenerate these
# together with a ``MODEL_VERSION`` bump; the published set must match byte for byte.
FETCH_SHA256: dict[str, str] = {
    "charge_encoder_encA.onnx": "b0003d88d3073bbd319d257b2c6048366c862f7fcfe562a9dd016fdfc0380a3d",
    "charge_encoder_encB.onnx": "e60c2835dbfe7ba19ab6b8d8445bd03944edc1db270e5b519d1e77c820b526c3",
    "multislot_head_encA.onnx": "a843c33ba1305801d11fb9ded04dc93ea4408c0aee912946dc9596b9aa8b4a62",
    "multislot_head_encB.onnx": "374d906000690083c1a991d8c5df3e614ff7d855d0eaaa112a57385aec852b63",
    "minilm-l6-v2/onnx/model.onnx": "759c3cd2b7fe7e93933ad23c4c9181b7396442a2ed746ec7c1d46192c469c46e",
    "minilm-l6-v2/tokenizer.json": "da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0",
}


class ModelFetchError(RuntimeError):
    """Raised when the model set cannot be fetched or verified."""


# ─── Presence + cache location ────────────────────────────────────────


def models_present(root: Path, relpaths: tuple[str, ...] = REQUIRED_RELPATHS) -> bool:
    """Whether every file in *relpaths* (default: the functional set) exists and is non-empty under *root*."""
    for rel in relpaths:
        f = root / rel
        try:
            if not f.is_file() or f.stat().st_size == 0:
                return False
        except OSError:
            return False
    return True


def cache_models_dir(version: str = MODEL_VERSION) -> Path:
    """The persistent cache dir for a model version: ``~/.reporails/cache/models/<version>/``."""
    from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir

    return get_global_cache_dir() / "models" / version


def offline_requested() -> bool:
    """Whether ``AILS_MODEL_OFFLINE`` asks to never download the model set."""
    return os.environ.get(_ENV_OFFLINE, "").strip().lower() not in ("", "0", "false", "no")


# One fetch at a time: concurrent first uses in one process (e.g. MCP worker threads) wait
# on the thread lock, and separate processes (parallel `ails` runs) wait on a per-version
# lock file in the cache dir, so only one of them downloads a given model version. Where
# the filesystem has no file locking, only the in-process lock applies.
_FETCH_LOCK = threading.Lock()

# A run that finds the lock taken waits this long before saying it is waiting, so a lock
# held only for a moment prints nothing.
_ANNOUNCE_AFTER_S = 2.0

# While waiting, the lock is retried at this interval. The wait lasts as long as the other
# download keeps growing; once it has not grown for _STALL_S, this run stops waiting and
# downloads the model itself.
_WAIT_POLL_S = 2.0
_STALL_S = 10 * 60


def _lock_path(cache_dir: Path, version: str) -> Path:
    return cache_dir / f".{version}.lock"


@functools.cache
def _file_lock_class() -> type:
    """A ``FileLock`` that raises ``NotImplementedError`` where the filesystem has no file locking."""
    from filelock import FileLock

    class _HardFileLock(FileLock):
        def _fallback_to_soft_lock(self) -> None:
            raise NotImplementedError("file locking is not supported on this filesystem")

    return _HardFileLock


@contextmanager
def _fetch_lock(cache_dir: Path, version: str) -> Iterator[None]:
    """Hold the in-process lock and, where the filesystem supports it, the ``.<version>.lock`` file lock."""
    with _FETCH_LOCK:
        cache_dir.mkdir(parents=True, exist_ok=True)
        lock = _file_lock_class()(str(_lock_path(cache_dir, version)))
        held = _acquire_file_lock(lock, cache_dir, version)
        try:
            yield
        finally:
            if held:
                lock.release()


def _acquire_file_lock(lock: Any, cache_dir: Path, version: str) -> bool:
    """Take *lock*, waiting while another process's download of *version* makes progress.

    Returns False without the lock when the filesystem has no file locking, or when the
    other download has stopped making progress; the caller then downloads on its own.
    """
    from filelock import Timeout

    try:
        try:
            lock.acquire(timeout=_ANNOUNCE_AFTER_S)
            return True
        except Timeout:
            _print("Waiting for another reporails model download to finish…")
        return _wait_while_progressing(lock, cache_dir, version)
    except (NotImplementedError, OSError):
        return False


def _wait_while_progressing(lock: Any, cache_dir: Path, version: str) -> bool:
    """Retry *lock* while the other download grows.

    Returns False once the model set is in place (another run finished it) or the other
    download has stalled for ``_STALL_S``.
    """
    from filelock import Timeout

    seen = _staged_bytes(cache_dir, version)
    last_progress = time.monotonic()
    while True:
        try:
            lock.acquire(timeout=_WAIT_POLL_S)
            return True
        except Timeout:
            pass
        if models_present(cache_dir / version):
            return False
        now = _staged_bytes(cache_dir, version)
        if now != seen:
            seen, last_progress = now, time.monotonic()
        elif time.monotonic() - last_progress >= _STALL_S:
            _print(
                f"The other reporails model download has made no progress for {_STALL_S // 60} minutes; "
                "downloading the model here instead…"
            )
            return False


def _staged_bytes(cache_dir: Path, version: str) -> int:
    """Bytes written so far into the in-progress downloads of *version*."""
    total = 0
    for f in cache_dir.glob(f".{version}.staging.*/**/*"):
        try:
            if f.is_file():
                total += f.stat().st_size
        except OSError:
            continue
    return total


def download_in_progress(version: str = MODEL_VERSION) -> bool:
    """Whether a download of *version* is running now, in this process or another."""
    if _FETCH_LOCK.locked():
        return True
    lock_path = _lock_path(cache_models_dir(version).parent, version)
    if not lock_path.exists():
        return False
    from filelock import Timeout

    lock = _file_lock_class()(str(lock_path))
    try:
        lock.acquire(timeout=0)
    except Timeout:
        return True
    except (OSError, NotImplementedError):
        return False
    lock.release()
    return False


def ensure_models_present(version: str = MODEL_VERSION) -> Path:
    """Return the cache dir for *version*, fetching the set first if absent.

    Idempotent: a populated cache is returned untouched (silent, offline); an empty or
    partial cache triggers a one-time download. A fetch failure raises
    :class:`ModelFetchError` and never leaves a partial artifact behind.
    """
    root = cache_models_dir(version)
    if models_present(root):
        return root
    try:
        with _fetch_lock(root.parent, version):
            if not models_present(root):
                _download_all(root, version)
    except OSError as exc:
        raise ModelFetchError(f"could not create the model cache at {root.parent}: {exc}") from exc
    return root


def repair_cache(version: str = MODEL_VERSION) -> Path:
    """Re-verify every cached file for *version* against its pin and re-download any mismatch.

    Unlike :func:`ensure_models_present`, this never trusts presence alone — a same-size
    corrupted file passes :func:`models_present` but fails to load. Called once after such
    a load failure, then the caller retries its load. Re-verifies every pin again after
    taking the fetch lock, so a peer that already repaired the set while this call waited
    is detected and nothing is downloaded or swapped — the one that loses the lock never
    redoes the swap. ``AILS_MODEL_OFFLINE`` means never download here either: raises first.
    """
    if offline_requested():
        raise ModelFetchError(
            "the model cache is damaged and AILS_MODEL_OFFLINE is set, so it cannot be repaired: "
            "unset AILS_MODEL_OFFLINE, or restore the file yourself."
        )
    root = cache_models_dir(version)
    try:
        with _fetch_lock(root.parent, version):
            if _verified_files(root) != frozenset(FETCH_SHA256):
                _download_all(root, version, force=True)
    except OSError as exc:
        raise ModelFetchError(f"could not repair the model cache at {root.parent}: {exc}") from exc
    return root


def cache_damaged(version: str = MODEL_VERSION) -> bool:
    """Whether *version*'s persistent cache has a missing or corrupted pinned file.

    True is exactly the shape :func:`repair_cache` fixes: a required file absent, or
    present but failing its pinned sha256. False means every required file matches its
    pin, so a load failure has a different cause that re-fetching the same bytes cannot
    repair (an incompatible ONNX Runtime, a missing dependency, an out-of-memory kill)."""
    root = cache_models_dir(version)
    verified = _verified_files(root)
    return any(rel not in verified for rel in REQUIRED_RELPATHS)


# ─── URL builder ──────────────────────────────────────────────────────


def _base_url(version: str) -> str:
    """Resolved host base URL: the env override if set, else the default host."""
    override = os.environ.get(_ENV_URL, "").strip()
    if override:
        return override.rstrip("/")
    return _DEFAULT_BASE.format(version=version)


def _auth_headers(base: str, version: str) -> dict[str, str]:
    """The user's API key as a bearer header when *base* is the default host.

    Empty for any other base — a mirror never receives the key — and when no
    key applies (none set, or one for a non-default diagnostics server).
    """
    if base != _DEFAULT_BASE.format(version=version):
        return {}
    from reporails_cli.core.platform.adapters.api_client import default_server_api_key

    key = default_server_api_key()
    return {"Authorization": f"Bearer {key}"} if key else {}


def asset_name(rel: str) -> str:
    """Flatten a models-root-relative path to a single host asset key.

    Flattening (``/`` → ``__``) gives every file one flat key, so any host that
    serves a flat directory of files — a static mirror or a release page
    — can serve the set unchanged.
    """
    return rel.replace("/", "__")


def _remote_url(base: str, rel: str) -> str:
    return f"{base}/{asset_name(rel)}"


# ─── Fetch ────────────────────────────────────────────────────────────


def check_response_head(rel: str, url: str, content_type: str, head: bytes) -> None:
    """Reject a response that is an HTML page or an empty body instead of the artifact.

    The HTML guard is load-bearing: a 200 interstitial (a redirect/login page reached via
    ``follow_redirects``, or a captive proxy) must never be written as a model artifact —
    it would pass the presence check and fail only at model-load time."""
    if not head:
        raise ModelFetchError(f"fetch of {rel} returned an empty body from {url}")
    ctype = content_type.lower()
    if "text/html" in ctype or head[:64].lstrip().lower().startswith((b"<!doctype", b"<html")):
        raise ModelFetchError(
            f"fetch of {rel} returned an HTML page (content-type {ctype!r}), not the artifact "
            "— likely a redirect/interstitial rather than the model host"
        )


def _download_one(client: httpx.Client, base: str, rel: str, target: Path) -> None:
    """Stream one file to *target*, verifying its pinned sha256 when one is set.

    A busy-host answer (429 / 503) is retried after its ``Retry-After`` (capped), up to
    ``_MAX_ATTEMPTS`` attempts; any other non-200 fails at once."""
    url = _remote_url(base, rel)
    target.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        with client.stream("GET", url) as resp:
            status = resp.status_code
            if status == 200:
                actual = _write_body(resp, rel, url, target)
                break
            if status not in _RETRY_STATUSES or attempt == _MAX_ATTEMPTS:
                busy = " — the model host is busy; try again in a minute" if status in _RETRY_STATUSES else ""
                raise ModelFetchError(f"fetch of {rel} failed: HTTP {status} from {url}{busy}")
            wait = _retry_wait(resp.headers.get("retry-after", ""))
        _print(f"  model host busy (HTTP {status}), retrying in {wait}s…")
        time.sleep(wait)
    expected = FETCH_SHA256.get(rel)
    if expected is None and rel in REQUIRED_RELPATHS:
        raise ModelFetchError(f"no pinned checksum for {rel}; refusing an unverified model file")
    if expected and actual != expected:
        raise ModelFetchError(
            f"fetch of {rel} from {url} does not match the expected checksum (sha256 {actual}, expected {expected})"
        )


def _write_body(resp: httpx.Response, rel: str, url: str, target: Path) -> str:
    """Stream a 200 response body to *target*; return its sha256 hex digest."""
    digest = hashlib.sha256()
    chunks = resp.iter_bytes(_CHUNK)
    head = next(chunks, b"")
    check_response_head(rel, url, resp.headers.get("content-type", ""), head)
    with target.open("wb") as out:
        out.write(head)
        digest.update(head)
        for chunk in chunks:
            out.write(chunk)
            digest.update(chunk)
    return digest.hexdigest()


def _retry_wait(retry_after: str) -> int:
    """Seconds to wait before a retry: the ``Retry-After`` delta, clamped to 1..60 (30 when absent)."""
    try:
        seconds = int(retry_after.strip())
    except ValueError:
        seconds = 30
    return max(1, min(seconds, _MAX_RETRY_WAIT_S))


def _download_all(root: Path, version: str, *, force: bool = False) -> None:
    """Download the set into a temp staging dir, then swap it into place.

    Staging into a sibling temp dir and renaming makes the swap safe: each run stages into
    its own unique dir, and the rename is atomic. A run that finds the cache already
    populated (a peer won the race) keeps the peer's copy and discards its own staging.
    Repairing an incomplete cache keeps every file that still matches its pinned sha256 and
    downloads only the rest. *force* (from :func:`repair_cache`) always swaps in, even
    though *root* looks complete by size — a same-size content corruption the presence
    check cannot see, which is exactly what a forced repair is fixing.
    """
    base = _base_url(version)
    total = len(FETCH_RELPATHS)
    parent = root.parent
    staging: Path | None = None
    try:
        parent.mkdir(parents=True, exist_ok=True)
        _sweep_stale_staging(parent, version)
        kept = _verified_files(root)
        if kept:
            _print(f"Repairing reporails model ({len(kept)} of {len(FETCH_SHA256)} checked files still valid)…")
        else:
            _print(f"Downloading reporails model (~{_APPROX_TOTAL_MB} MB, one time)…")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            _print(_CI_CACHE_HINT)
        staging = Path(tempfile.mkdtemp(prefix=f".{version}.staging.", dir=parent))
        with _http_client(_auth_headers(base, version)) as client:
            for i, rel in enumerate(FETCH_RELPATHS, start=1):
                if rel in kept:
                    _print(f"  [{i}/{total}] {rel} (kept)")
                    _link_or_copy(root / rel, staging / rel)
                    continue
                _print(f"  [{i}/{total}] {rel}")
                _download_one(client, base, rel, staging / rel)

        if not models_present(staging):
            missing = [r for r in REQUIRED_RELPATHS if not (staging / r).is_file()]
            raise ModelFetchError(f"model fetch completed but is missing files: {missing}")

        _swap_into_place(staging, root, force=force)
        _prune_old_versions(parent, version)
    except ModelFetchError:
        raise
    except PermissionError as exc:
        raise ModelFetchError(f"could not write the model cache at {parent}: {exc}") from exc
    except Exception as exc:
        raise ModelFetchError(
            f"could not download the reporails model from {base}: {exc}. "
            f"Check your network connection, or set {_ENV_URL} to a reachable model host "
            f"({_ENV_OFFLINE}=1 runs without downloading)."
        ) from exc
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verified_files(root: Path) -> frozenset[str]:
    """Files already under *root* whose sha256 matches their pin (reused by a repair)."""
    if not root.is_dir():
        return frozenset()
    kept = set()
    for rel, expected in FETCH_SHA256.items():
        path = root / rel
        try:
            if path.is_file() and _file_sha256(path) == expected:
                kept.add(rel)
        except OSError:
            continue
    return frozenset(kept)


def _link_or_copy(src: Path, dst: Path) -> None:
    """Hard-link *src* to *dst* (same filesystem), else copy it."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def _prune_old_versions(parent: Path, version: str) -> None:
    """Keep *version* and the most recently written other model set; remove the rest.

    Best effort: a failure here never fails the fetch that preceded it."""
    others = []
    try:
        entries = list(parent.iterdir())
    except OSError:
        return
    for d in entries:
        try:
            if d.is_dir() and not d.name.startswith(".") and d.name != version:
                others.append((d.stat().st_mtime, d))
        except OSError:
            continue
    others.sort(reverse=True)
    for _mtime, d in others[1:]:
        shutil.rmtree(d, ignore_errors=True)


def _sweep_stale_staging(parent: Path, version: str) -> None:
    """Remove staging dirs a killed run left behind (older than ``_STALE_STAGING_S``)."""
    cutoff = time.time() - _STALE_STAGING_S
    for d in parent.glob(f".{version}.staging.*"):
        try:
            if d.is_dir() and d.stat().st_mtime < cutoff:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            continue


def _swap_into_place(staging: Path, root: Path, *, force: bool = False) -> None:
    """Move *staging* to *root*; yield to a peer that already populated it.

    A *root* left incomplete (a file deleted or quarantined after install) is removed
    first, so the fresh set replaces it instead of failing the rename. *force* skips the
    "already populated" yield — a forced repair already knows *root* looks complete by
    size and is replacing it anyway.
    """
    if not force and models_present(root):
        return  # a concurrent run won the race — keep its copy
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
    try:
        os.replace(staging, root)  # atomic rename within the same filesystem
    except OSError:
        # root appeared (non-empty) between the check and the rename; take a peer's copy.
        if not force and models_present(root):
            return
        raise


def _http_client(headers: dict[str, str] | None = None) -> httpx.Client:
    import httpx

    return httpx.Client(timeout=120.0, follow_redirects=True, headers=headers)


def _print(msg: str) -> None:
    """First-run progress goes to stderr — stdout carries ``--json`` output."""
    print(msg, file=sys.stderr, flush=True)
