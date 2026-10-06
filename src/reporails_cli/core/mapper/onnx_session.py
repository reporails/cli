"""ONNX Runtime session + tokenizer setup for a bundled ONNX graph.

Folds the CPU-tuned `SessionOptions`, bundled-tokenizer load, and
`token_type_ids`-presence probe into one base class; each subclass resolves its
own graph path + max length and adds the forward pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, NamedTuple

# Texts tokenized per call when counting tokens for bucket ordering.
_COUNT_CHUNK = 1024


class _Tokens(NamedTuple):
    """One text with its token ids and per-token character offsets (no padding)."""

    text: str
    ids: list[int]
    offsets: list[tuple[int, int]]


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

        # Whether this particular model graph takes token_type_ids as an input.
        self._needs_token_type_ids = any(i.name == "token_type_ids" for i in self._session.get_inputs())

    def plan_buckets(self, texts: list[str], bucket_size: int) -> tuple[list[list[str]], list[int]]:
        """Group the distinct ``texts`` into buckets of similar token count, longest first.

        Returns ``(buckets, slot)``: each distinct text appears in exactly one bucket;
        ``slot[i]`` is the position of ``texts[i]`` in the concatenation of the
        buckets, so ``flat[slot[i]]`` is the result for input ``i`` (duplicate inputs
        share one slot). Token counts are taken in fixed-size chunks and only the
        counts are kept; `_tokenize` builds the tokens of one bucket on demand.
        """
        unique = list(dict.fromkeys(texts))
        if not unique:
            return [], []
        counts: list[int] = []
        for s in range(0, len(unique), _COUNT_CHUNK):
            encs = self._tokenizer.encode_batch(unique[s : s + _COUNT_CHUNK])
            counts.extend(sum(e.attention_mask) for e in encs)
        order = sorted(range(len(unique)), key=lambda k: -counts[k])
        position = {k: pos for pos, k in enumerate(order)}
        index = {t: position[k] for k, t in enumerate(unique)}
        ordered = [unique[k] for k in order]
        buckets = [ordered[s : s + bucket_size] for s in range(0, len(ordered), bucket_size)]
        return buckets, [index[t] for t in texts]

    def _tokenize(self, texts: list[str]) -> list[_Tokens]:
        """Tokenize one bucket's ``texts`` (truncated, padding stripped)."""
        tokens: list[_Tokens] = []
        for t, e in zip(texts, self._tokenizer.encode_batch(texts), strict=True):
            n = sum(e.attention_mask)
            tokens.append(_Tokens(t, e.ids[:n], list(e.offsets[:n])))
        return tokens

    def _encode_feed(self, bucket: list[_Tokens]) -> dict[str, Any]:
        """Build the ORT feed (int64 ids / attention mask / type-ids) for one bucket, zero-padded."""
        import numpy as np

        width = max(len(t.ids) for t in bucket)
        ids = np.zeros((len(bucket), width), dtype=np.int64)
        masks = np.zeros((len(bucket), width), dtype=np.int64)
        for i, t in enumerate(bucket):
            ids[i, : len(t.ids)] = t.ids
            masks[i, : len(t.ids)] = 1
        feed: dict[str, Any] = {"input_ids": ids, "attention_mask": masks}
        if self._needs_token_type_ids:
            feed["token_type_ids"] = np.zeros_like(ids)
        return feed
