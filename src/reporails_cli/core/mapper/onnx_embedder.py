"""Bundled sentence embedder, run on CPU from a model graph shipped with the download.

Token-count bucketing
---------------------

The dominant CPU cost scales with the padded sequence length. Distinct texts are
grouped into ``_BUCKET_SIZE`` buckets of similar token count, each encoded with tight
padding, and scattered back into the caller's order (duplicates share one row).

Order is preserved — callers see an ``ndarray`` where row ``i`` is the
embedding of ``texts[i]``.
"""

from __future__ import annotations

from collections.abc import Callable

import numpy as np
import numpy.typing as npt

from reporails_cli.core.mapper.encode_pool import run_buckets
from reporails_cli.core.mapper.model_manifest import get_models_path
from reporails_cli.core.mapper.model_store import reload_after_repair
from reporails_cli.core.mapper.onnx_session import _OnnxEncoderSession

# Fixed settings of the bundled embedder
_HIDDEN_DIM = 384
_MAX_LENGTH = 128  # longest input, in tokens
_BUCKET_SIZE = 16  # atoms encoded together
_DEFAULT_MODEL_SUBDIR = "minilm-l6-v2"


class OnnxEmbedder(_OnnxEncoderSession):
    """Embeds texts with the bundled ONNX model.

    ``encode(texts: list[str]) -> np.ndarray`` returns L2-normalised float32
    embeddings, one row per text, in the same order as ``texts``.
    """

    def __init__(self) -> None:
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

        reload_after_repair(lambda: self._init_session(onnx_path, tokenizer_path, _MAX_LENGTH))

    def encode(self, texts: list[str]) -> npt.NDArray[np.float32]:
        """Encode ``texts`` to L2-normalised float32 embeddings.

        Each distinct text is encoded once, in buckets of similar token count.
        Output row ``i`` corresponds to ``texts[i]`` (original order).
        """
        n = len(texts)
        if n == 0:
            return np.empty((0, _HIDDEN_DIM), dtype=np.float32)

        buckets, slot = self.plan_buckets(texts, _BUCKET_SIZE)

        def _bucket(bucket: list[str]) -> Callable[[], npt.NDArray[np.float32]]:
            return lambda: self._encode_batch(bucket)

        flat = np.concatenate(run_buckets([_bucket(b) for b in buckets]))
        return flat[slot]

    def _encode_batch(self, bucket: list[str]) -> npt.NDArray[np.float32]:
        """Tokenize one bucket of texts, forward it through the graph, mean-pool and L2-normalise."""
        feed = self.encode_feed(self.tokenize(bucket))
        masks = feed["attention_mask"]

        # Last hidden state: (B, T_max, hidden)
        last_hidden = self._session.run(None, feed)[0]

        # Mean-pool across valid tokens using the attention mask as weights.
        mask_f = masks[:, :, None].astype(np.float32)  # (B, T_max, 1)
        summed = (last_hidden * mask_f).sum(axis=1)  # (B, hidden)
        counts = mask_f.sum(axis=1).clip(min=1e-9)  # (B, 1)
        pooled = summed / counts  # (B, hidden)

        # L2 normalise (same convention as sentence-transformers default).
        norms = np.linalg.norm(pooled, axis=-1, keepdims=True).clip(min=1e-12)
        normalised: npt.NDArray[np.float32] = (pooled / norms).astype(np.float32)
        return normalised
