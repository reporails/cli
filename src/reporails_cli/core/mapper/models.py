"""Lazy-loaded ML model singleton — spaCy `en_core_web_sm` + ONNX MiniLM-L6-v2.

Loaded once per process, reused across files. Both loads are guarded by per-attribute
locks so the daemon's background warmup thread and a serving thread can't
double-initialise the same model.

Public entry point: `get_models()` returns the process-wide singleton.

Stage 3 (classify) consumes `.nlp`; Stage 5 (embed) consumes `.st`. Either can
be `None`/missing without the other — spaCy gracefully degrades to a lexicon
fallback in classify, ONNX is mandatory for embed.
"""

from __future__ import annotations

from typing import Any

_UNSET = object()


class Models:
    """Lazy-loaded models. Load once, reuse across files.

    Thread-safe: both ``.st`` and ``.nlp`` lazy loads are guarded by a lock
    so the daemon's background warmup thread and a serving thread can't
    double-initialise the same model.
    """

    def __init__(self) -> None:
        import threading as _threading

        self._st: Any | None = None
        self._nlp: Any = _UNSET
        self._st_lock = _threading.Lock()
        self._nlp_lock = _threading.Lock()

    @property
    def st(self) -> Any:
        if self._st is None:
            with self._st_lock:
                if self._st is None:
                    # ONNX Runtime directly on the bundled MiniLM-L6-v2 ONNX
                    # export — no torch, no sentence-transformers. Loads in
                    # ~0.3s (vs ~20s for `import torch`), produces bit-identical
                    # output to the PyTorch reference (float32 epsilon).
                    # ORT and PyTorch hit the SAME per-atom throughput on this
                    # model (~67 atoms/s bs=32, ~86 atoms/s length-sorted) —
                    # both dispatch to MLAS kernels. The torch import cost was
                    # the only real bottleneck, and the _torch_blocker hook at
                    # CLI/MCP/daemon entry points eliminates it.
                    try:
                        from reporails_cli.core.mapper.onnx_embedder import OnnxEmbedder
                    except ImportError as exc:
                        raise RuntimeError("onnxruntime / tokenizers not installed.\nRun: uv sync") from exc
                    self._st = OnnxEmbedder()
        return self._st

    @property
    def nlp(self) -> Any | None:
        if self._nlp is _UNSET:
            with self._nlp_lock:
                if self._nlp is _UNSET:
                    try:
                        import spacy

                        # Phase 3 classification only reads tok.dep_ / tok.tag_ /
                        # tok.text / tok.i / root.children. That needs tok2vec +
                        # tagger + parser only; ner / lemmatizer / attribute_ruler
                        # are dead weight on both load time and per-doc inference.
                        try:
                            self._nlp = spacy.load(
                                "en_core_web_sm",
                                disable=["ner", "lemmatizer", "attribute_ruler"],
                            )
                        except OSError:
                            # Model not installed — download it once
                            import subprocess
                            import sys

                            subprocess.run(
                                [sys.executable, "-m", "spacy", "download", "en_core_web_sm"],
                                capture_output=True,
                            )
                            self._nlp = spacy.load(
                                "en_core_web_sm",
                                disable=["ner", "lemmatizer", "attribute_ruler"],
                            )
                    except (ImportError, OSError):
                        self._nlp = None
        return self._nlp

    def warmup(self) -> None:
        """Eagerly load both models in parallel.

        Both loads are CPU-bound in native code that releases the GIL, so
        threads actually parallelise. Saves roughly ``min(T_spacy, T_st)``
        on cold start. Idempotent — safe to call multiple times.
        """
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_st = pool.submit(lambda: self.st)
            fut_nlp = pool.submit(lambda: self.nlp)
            # Surface exceptions from the ST load (nlp load already tolerates
            # ImportError/OSError and stores None).
            fut_st.result()
            fut_nlp.result()


_models: Models | None = None


def get_models() -> Models:
    """Get or create the lazy model singleton."""
    global _models
    if _models is None:
        _models = Models()
    return _models
