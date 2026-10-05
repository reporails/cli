"""ONNX Runtime session + tokenizer setup for a bundled ONNX graph.

Folds the CPU-tuned `SessionOptions`, bundled-tokenizer load, and
`token_type_ids`-presence probe into one base class; each subclass resolves its
own graph path + max length and adds the forward pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class _OnnxEncoderSession:
    """ONNX Runtime session + tokenizer over a bundled ONNX graph.

    Subclasses resolve and existence-check their own graph + tokenizer paths, then
    call `_init_session(...)` from `__init__`; afterwards `self._session`,
    `self._tokenizer`, and `self._needs_token_type_ids` are ready for the forward
    pass the subclass implements.
    """

    _session: Any
    _tokenizer: Any
    _needs_token_type_ids: bool

    def _init_session(
        self,
        onnx_path: Path,
        tokenizer_path: Path,
        max_length: int,
        threads: int | None = None,
    ) -> None:
        """Build the CPU-tuned ORT session and configure the bundled tokenizer."""
        # Local imports so the module imports cheaply without pulling ORT up-front.
        import onnxruntime as ort
        from tokenizers import Tokenizer

        # Session options tuned for CPU inference.
        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        from reporails_cli.core.mapper.encode_pool import ort_intra_threads

        opts.intra_op_num_threads = ort_intra_threads() if threads is None else int(threads)
        opts.inter_op_num_threads = 1
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        opts.enable_cpu_mem_arena = True
        opts.enable_mem_pattern = True
        opts.enable_mem_reuse = True

        self._session = ort.InferenceSession(
            str(onnx_path),
            sess_options=opts,
            providers=["CPUExecutionProvider"],
        )

        self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        self._tokenizer.enable_truncation(max_length=max_length)
        self._tokenizer.enable_padding(pad_id=0, pad_token="[PAD]", length=None)

        # Whether this particular model graph takes token_type_ids as an input.
        self._needs_token_type_ids = any(i.name == "token_type_ids" for i in self._session.get_inputs())

    def _encode_feed(self, batch: list[str]) -> dict[str, Any]:
        """Tokenize a batch into the ORT feed dict (int64 ids/mask/type-ids)."""
        import numpy as np

        encs = self._tokenizer.encode_batch(batch)
        ids = np.array([e.ids for e in encs], dtype=np.int64)
        masks = np.array([e.attention_mask for e in encs], dtype=np.int64)
        feed: dict[str, Any] = {"input_ids": ids, "attention_mask": masks}
        if self._needs_token_type_ids:
            feed["token_type_ids"] = np.zeros_like(ids)
        return feed
