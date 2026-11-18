"""Content-hash fingerprint of the model graph files, memoized on disk."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_object

# ──────────────────────────────────────────────────────────────────
# Content-hash fingerprint, memoized on disk: hashing the graphs cold on every
# process would be paid on every `ails check`, even a whole-map cache hit, and
# again per shard worker.
# ──────────────────────────────────────────────────────────────────

_SIDECAR_NAME = "fingerprint.json"

# Guards the sidecar's read-modify-write: `graph_content_hash` is safe to call from several
# threads at once, and two threads writing the file at once would corrupt it.
# Reentrant: `graph_content_hash` holds it across its own calls into `_load_sidecar` / `_save_sidecar`.
_sidecar_lock = threading.RLock()


def _sidecar_paths() -> list[Path]:
    """Where the on-disk fingerprint sidecar lives: the user's global cache directory.

    Never the models directory: a run must not write into the installed package or a
    source checkout. The sidecar is keyed by each graph's full path, so one file serves
    every models location.
    """
    return [get_global_cache_dir() / _SIDECAR_NAME]


def _load_sidecar() -> JsonObject:
    """Read the sidecar from disk; ``{}`` when no candidate path is readable."""
    with _sidecar_lock:
        for path in _sidecar_paths():
            try:
                loaded: JsonValue = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    return loaded
            except (OSError, ValueError):
                continue
        return {}


def _save_sidecar(sidecar: JsonObject) -> None:
    """Best-effort persist of the sidecar — a perf cache only, never
    load-bearing for correctness (a write failure just costs the next process
    a re-hash)."""
    with _sidecar_lock:
        payload = json.dumps(sidecar)
        for path in _sidecar_paths():
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(payload, encoding="utf-8")
                return
            except OSError:
                continue


def _hash_file_bytes(path: Path) -> str:
    """The actual (expensive) content hash — isolated so a test can count calls."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def graph_content_hash(path: Path) -> str:
    """sha256 hex digest of a graph/sidecar file's bytes.

    Memoized on disk: the on-disk sidecar (:func:`_load_sidecar` / :func:`_save_sidecar`) is
    keyed by (path, size, mtime), so the hash is computed once per install, not once per
    process. Content hash rather than bare size+mtime — mtime is not stable across install
    methods (pip wheel extraction, npx cache re-copy, git checkout), so two installs of the
    identical weights could otherwise fingerprint differently, or (worse) two DIFFERENT
    weight exports could coincidentally share a size+mtime pair.
    """
    st = path.stat()
    with _sidecar_lock:
        key = str(path)
        sidecar = _load_sidecar()
        entry = as_object(sidecar.get(key))
        if entry and entry.get("size") == st.st_size and entry.get("mtime") == st.st_mtime:
            return str(entry["digest"])
        digest = _hash_file_bytes(path)
        sidecar[key] = {"size": st.st_size, "mtime": st.st_mtime, "digest": digest}
        _save_sidecar(sidecar)
        return digest
