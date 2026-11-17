"""Lazy-loaded resource handle for the mapper — the bundled embedder, encoders and heads.

A `Models` holds the loaded models and loads each on first access. Each load is
lock-guarded so two threads asking for the same model can't double-initialise it.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.platform.contract.http_get import HttpGet

if TYPE_CHECKING:
    import onnxruntime as ort

    from reporails_cli.core.mapper.bio_tagger import _BioEncoder
    from reporails_cli.core.mapper.onnx_embedder import OnnxEmbedder

logger = logging.getLogger(__name__)


class Models:
    """Lazy-loaded model handle.

    Load once, reuse across files. A model file damaged since the process started is
    re-downloaded through `fetch` when the next load needs it.
    """

    def __init__(self, fetch: HttpGet) -> None:
        self.fetch = fetch
        self._st: OnnxEmbedder | None = None
        self._st_lock = threading.Lock()
        self._charge: tuple[_BioEncoder, _BioEncoder] | None = None
        self._charge_lock = threading.Lock()
        self._heads: dict[str, ort.InferenceSession] = {}
        self._heads_lock = threading.Lock()

    @property
    def st(self) -> OnnxEmbedder:
        """The loaded embedder, loading it on first access."""
        if self._st is None:
            with self._st_lock:
                if self._st is None:
                    # The bundled embedder, loaded directly from its shipped graph.
                    from reporails_cli.core.mapper.onnx_embedder import (  # pylint: disable=import-outside-toplevel  # ML runtime loads on first model use
                        OnnxEmbedder,
                    )

                    self._st = OnnxEmbedder(self.fetch)
        return self._st

    def charge_encoders(self) -> tuple[_BioEncoder, _BioEncoder]:
        """The two encoders, loading them on first access."""
        if self._charge is None:
            with self._charge_lock:
                if self._charge is None:
                    from reporails_cli.core.mapper.bio_graphs import (  # pylint: disable=import-outside-toplevel  # ML runtime loads on first model use
                        _enc_a_path,
                        _enc_b_path,
                    )
                    from reporails_cli.core.mapper.bio_tagger import (  # pylint: disable=import-outside-toplevel  # ML runtime loads on first model use
                        _BioEncoder,
                    )
                    from reporails_cli.core.mapper.model_store import (  # pylint: disable=import-outside-toplevel  # ML runtime loads on first model use
                        reload_after_repair,
                    )

                    enc_a = reload_after_repair(lambda: _BioEncoder(_enc_a_path()), self.fetch)
                    enc_b = reload_after_repair(lambda: _BioEncoder(_enc_b_path()), self.fetch)
                    self._charge = (enc_a, enc_b)
        return self._charge

    def head_session(self, head: Path) -> ort.InferenceSession:
        """The inference session of the head graph at `head`, loading it on first access."""
        key = str(head)
        with self._heads_lock:
            session = self._heads.get(key)
            if session is None:
                from reporails_cli.core.mapper.bio_tagger import (  # pylint: disable=import-outside-toplevel  # ML runtime loads on first model use
                    _build_head_session,
                )
                from reporails_cli.core.mapper.model_store import (  # pylint: disable=import-outside-toplevel  # ML runtime loads on first model use
                    reload_after_repair,
                )

                session = reload_after_repair(lambda: _build_head_session(key), self.fetch)
                self._heads[key] = session
        return session

    def warmup(self) -> None:
        """Eagerly load the embedder so the first embed call is fast.
        Idempotent — safe to call repeatedly.
        """
        _ = self.st

    def unload(self) -> None:
        """Drop the loaded embedder so its memory is reclaimed; next access reloads."""
        with self._st_lock:
            self._st = None
