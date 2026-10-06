"""Lazy-loaded resource handle for the mapper — the bundled embedder.

`.st` lazily loads the bundled embedder.
`get_models()` returns the process-wide singleton; the load is lock-guarded so the
daemon's background warmup thread and a serving thread can't double-initialise it.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class Models:
    """Lazy-loaded embedder handle.

    Load once, reuse across files. The load is guarded by a lock so the
    daemon's background warmup thread and a serving thread can't
    double-initialise the model.
    """

    def __init__(self) -> None:
        self._st: Any | None = None
        self._st_lock = threading.Lock()

    @property
    def st(self) -> Any:
        if self._st is None:
            with self._st_lock:
                if self._st is None:
                    # The bundled embedder, loaded directly from its shipped graph.
                    try:
                        from reporails_cli.core.mapper.onnx_embedder import OnnxEmbedder
                    except ImportError as exc:
                        raise RuntimeError("onnxruntime / tokenizers not installed.\nRun: uv sync") from exc
                    self._st = OnnxEmbedder()
        return self._st

    def warmup(self) -> None:
        """Eagerly load the embedder so the first embed call is fast.
        Idempotent — safe to call repeatedly.
        """
        _ = self.st

    def unload(self) -> None:
        """Drop the loaded embedder so its memory is reclaimed; next access reloads."""
        with self._st_lock:
            self._st = None


_models: Models | None = None


def get_models() -> Models:
    """Get or create the process-wide resource handle."""
    global _models
    if _models is None:
        _models = Models()
    return _models
