"""Bundled sentence embedder, run on CPU from a model graph shipped with the download.

Length-sorted batching
----------------------

The dominant CPU cost scales with the padded sequence length. When atoms in a batch
have wildly different lengths, the short ones pad up to the longest and waste compute
on pad tokens.

Atoms are therefore sorted by approximate token length before batching, split into
``BUCKET_SIZE`` chunks, encoded with tight dynamic padding, and scattered back into
the caller's original order.

Order is preserved — callers see an ``ndarray`` where row ``i`` is the
embedding of ``texts[i]``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.mapper.onnx_session import _MiniLMOnnxSession

if TYPE_CHECKING:
    import numpy as np

# Fixed settings of the bundled embedder
_HIDDEN_DIM = 384
_MAX_LENGTH = 128  # longest input, in tokens
_BUCKET_SIZE = 16  # atoms encoded together
_DEFAULT_MODEL_SUBDIR = "minilm-l6-v2"


class OnnxEmbedder(_MiniLMOnnxSession):
    """Embeds texts with the bundled ONNX model.

    ``encode(texts: list[str]) -> np.ndarray`` returns L2-normalised float32
    embeddings, one row per text, in the same order as ``texts``.
    """

    def __init__(
        self,
        model_dir: Path | None = None,
        threads: int | None = None,
    ) -> None:
        from reporails_cli.bundled import get_models_path

        if model_dir is None:
            model_dir = get_models_path() / _DEFAULT_MODEL_SUBDIR

        onnx_path = model_dir / "onnx" / "model.onnx"
        tokenizer_path = model_dir / "tokenizer.json"
        if not onnx_path.is_file():
            raise RuntimeError(
                f"reporails model not found at {onnx_path}. Run `ails check` online once to "
                "fetch it, or unset AILS_MODEL_OFFLINE."
            )
        if not tokenizer_path.is_file():
            raise RuntimeError(
                f"reporails model tokenizer not found at {tokenizer_path}. Run `ails check` "
                "online once to fetch it, or unset AILS_MODEL_OFFLINE."
            )

        from reporails_cli.bundled import reload_after_repair

        reload_after_repair(lambda: self._init_session(onnx_path, tokenizer_path, _MAX_LENGTH, threads))

    def encode(self, texts: list[str]) -> np.ndarray:
        """Encode ``texts`` to L2-normalised float32 embeddings.

        Uses length-sorted bucketed batching for tight dynamic padding.
        Output row ``i`` corresponds to ``texts[i]`` (original order).
        """
        import numpy as np

        n = len(texts)
        if n == 0:
            return np.empty((0, _HIDDEN_DIM), dtype=np.float32)

        # Length-sort (ascending). We use character length as a cheap
        # proxy for token length — close enough for sort ordering and
        # avoids a full tokenization pass up front.
        indexed = sorted(enumerate(texts), key=lambda it: len(it[1]))
        sorted_idx = [i for i, _ in indexed]
        sorted_texts = [t for _, t in indexed]

        # Encode each bucket (concurrently over the warm session when the pool is
        # on), then scatter back to original order.
        sorted_out = self._encode_buckets(sorted_texts)

        result = np.empty((n, _HIDDEN_DIM), dtype=np.float32)
        for new_i, orig_i in enumerate(sorted_idx):
            result[orig_i] = sorted_out[new_i]
        return result

    # ──────────────────────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────────────────────

    def _encode_buckets(self, sorted_texts: list[str]) -> np.ndarray:
        """Encode length-sorted texts bucket-by-bucket, returning rows in sorted order.

        Buckets run concurrently over the one warm session when the pool is on;
        `run_buckets` preserves submission order, so the output is
        byte-identical to the old serial loop.
        """
        import numpy as np

        from reporails_cli.core.mapper.encode_pool import run_buckets

        n = len(sorted_texts)

        def _bucket(start: int) -> Callable[[], np.ndarray]:
            def run() -> np.ndarray:
                return self._encode_batch(sorted_texts[start : start + _BUCKET_SIZE])

            return run

        outs = run_buckets([_bucket(s) for s in range(0, n, _BUCKET_SIZE)])
        sorted_out = np.empty((n, _HIDDEN_DIM), dtype=np.float32)
        offset = 0
        for out in outs:
            sorted_out[offset : offset + len(out)] = out
            offset += len(out)
        return sorted_out

    def _encode_batch(self, batch: list[str]) -> np.ndarray:
        """Forward one bucket through the model graph + mean-pool + L2-normalise."""
        import numpy as np

        encs = self._tokenizer.encode_batch(batch)
        # (B, T_max) where T_max is the max length within this bucket
        ids = np.array([e.ids for e in encs], dtype=np.int64)
        masks = np.array([e.attention_mask for e in encs], dtype=np.int64)

        feed: dict[str, np.ndarray] = {"input_ids": ids, "attention_mask": masks}
        if self._needs_token_type_ids:
            feed["token_type_ids"] = np.zeros_like(ids)

        # Last hidden state: (B, T_max, hidden)
        last_hidden = self._session.run(None, feed)[0]

        # Mean-pool across valid tokens using the attention mask as weights.
        mask_f = masks[:, :, None].astype(np.float32)  # (B, T_max, 1)
        summed = (last_hidden * mask_f).sum(axis=1)  # (B, hidden)
        counts = mask_f.sum(axis=1).clip(min=1e-9)  # (B, 1)
        pooled = summed / counts  # (B, hidden)

        # L2 normalise (same convention as sentence-transformers default).
        norms = np.linalg.norm(pooled, axis=-1, keepdims=True).clip(min=1e-12)
        normalised: np.ndarray = (pooled / norms).astype(np.float32)
        return normalised
