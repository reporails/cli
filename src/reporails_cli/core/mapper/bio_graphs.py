"""Bundled classification model graph paths + content-hash fingerprinting.

Resolves the bundled model graph files and fingerprints them by content hash,
caching the hash per file.
"""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

# Bundled classification model file names, resolved to on-disk paths below.
# The axis-name aliases live in `bio_tagger._MULTISLOT_RENAME`, defined
# locally in that module — not restated here.
_ENC_A_NAME = "charge_encoder_encA.onnx"
_HEAD_A_NAME = "multislot_head_encA.onnx"
_ENC_B_NAME = "charge_encoder_encB.onnx"
_HEAD_B_NAME = "multislot_head_encB.onnx"


def _enc_a_path() -> Path:
    """Path to the bundled `_ENC_A_NAME` model file."""
    from reporails_cli.bundled import get_models_path

    return get_models_path() / _ENC_A_NAME


def _head_a_path() -> Path:
    """Path to the bundled `_HEAD_A_NAME` model file."""
    from reporails_cli.bundled import get_models_path

    return get_models_path() / _HEAD_A_NAME


def _enc_b_path() -> Path:
    """Path to the bundled `_ENC_B_NAME` model file."""
    from reporails_cli.bundled import get_models_path

    return get_models_path() / _ENC_B_NAME


def _head_b_path() -> Path:
    """Path to the bundled `_HEAD_B_NAME` model file."""
    from reporails_cli.bundled import get_models_path

    return get_models_path() / _HEAD_B_NAME


# ──────────────────────────────────────────────────────────────────
# Content-hash fingerprint, memoized on disk: hashing the graphs cold on every
# process would be paid on every `ails check`, even a whole-map cache hit, and
# again per shard worker.
# ──────────────────────────────────────────────────────────────────

# Per-process content-hash cache, keyed on (path, size, mtime) so a repeat call
# in the same process costs no re-read unless the file actually changed on disk
# (a size+mtime match is a cheap stat, not a re-hash).
_graph_hash_cache: dict[Path, tuple[int, float, str]] = {}

_SIDECAR_NAME = "fingerprint.json"
# Lazily-loaded, process-lifetime cache of the on-disk sidecar's contents —
# loaded once per process (not once per graph path) so a warm sidecar costs one
# file read, not six.
_sidecar_data: dict[str, Any] | None = None

# Guards every read-modify-write over `_graph_hash_cache` / `_sidecar_data`: on a cold
# cache (no sidecar file yet, or an unseen path) `_graph_content_hash` mutates the
# shared dict AND serializes it (`_save_sidecar`'s `json.dumps` walks it). The MCP
# server calls this from many worker threads at once (one per file's pipeline run);
# without a lock, one thread's dict mutation during another thread's `json.dumps` walk
# raises `RuntimeError: dictionary changed size during iteration` — surfaced to the
# caller as a swallowed "pipeline run produced no map". Reentrant: `_graph_content_hash`
# holds it across its own calls into `_load_sidecar` / `_save_sidecar`.
_sidecar_lock = threading.RLock()


def _sidecar_paths() -> list[Path]:
    """Where the on-disk fingerprint sidecar lives: the user's global cache directory.

    Never the models directory: a run must not write into the installed package or a
    source checkout. The sidecar is keyed by each graph's full path, so one file serves
    every models location.
    """
    from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir

    return [get_global_cache_dir() / _SIDECAR_NAME]


def _load_sidecar() -> dict[str, Any]:
    """Read the sidecar once per process; ``{}`` when no candidate path is readable."""
    global _sidecar_data
    with _sidecar_lock:
        if _sidecar_data is not None:
            return _sidecar_data
        for path in _sidecar_paths():
            try:
                _sidecar_data = json.loads(path.read_text())
                return _sidecar_data
            except (OSError, ValueError):
                continue
        _sidecar_data = {}
        return _sidecar_data


def _save_sidecar() -> None:
    """Best-effort persist of the in-memory sidecar — a perf cache only, never
    load-bearing for correctness (a write failure just costs the next process
    a re-hash, same as today)."""
    with _sidecar_lock:
        if _sidecar_data is None:
            return
        payload = json.dumps(_sidecar_data)
        for path in _sidecar_paths():
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(payload)
                return
            except OSError:
                continue


def _hash_file_bytes(path: Path) -> str:
    """The actual (expensive) content hash — isolated so a test can count calls."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _graph_content_hash(path: Path) -> str:
    """sha256 hex digest of a graph/sidecar file's bytes.

    Memoized twice: an in-memory (path, size, mtime) → digest cache for a
    repeat call in the SAME process, and an on-disk sidecar (:func:`_load_sidecar`
    / :func:`_save_sidecar`) keyed the same way so the hash is computed once per
    install, not once per process — a whole-map cache hit and every shard worker
    would otherwise each pay the full re-hash. Content hash rather than bare
    size+mtime — mtime is not stable across install methods (pip wheel
    extraction, npx cache re-copy, git checkout), so two installs of the
    identical weights could otherwise fingerprint differently, or (worse) two
    DIFFERENT weight exports could coincidentally share a size+mtime pair.
    """
    st = path.stat()
    with _sidecar_lock:
        cached = _graph_hash_cache.get(path)
        if cached is not None and cached[0] == st.st_size and cached[1] == st.st_mtime:
            return cached[2]

        key = str(path)
        sidecar = _load_sidecar()
        entry = sidecar.get(key)
        digest: str
        if entry and entry.get("size") == st.st_size and entry.get("mtime") == st.st_mtime:
            digest = str(entry["digest"])
        else:
            digest = _hash_file_bytes(path)
            sidecar[key] = {"size": st.st_size, "mtime": st.st_mtime, "digest": digest}
            _save_sidecar()

        _graph_hash_cache[path] = (st.st_size, st.st_mtime, digest)
        return digest
