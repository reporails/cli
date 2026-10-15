"""Span tagger for running text.

Runs the bundled encoders and heads over one line of text and decodes the span
axes it returns. Word-pooling and the softmax run in numpy, torch-free. Callers guard
on ``bio_graphs.multislot_available``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Literal, get_args

import numpy as np
import numpy.typing as npt

from reporails_cli.core.mapper.bio_graphs import (
    _enc_a_path,
    _enc_b_path,
)
from reporails_cli.core.mapper.encode_pool import ort_intra_threads
from reporails_cli.core.mapper.model_manifest import EMBEDDER_SUBDIR, get_models_path
from reporails_cli.core.mapper.model_store import reload_after_repair
from reporails_cli.core.mapper.onnx_session import _OnnxEncoderSession
from reporails_cli.core.mapper.word_spans import word_offsets
from reporails_cli.core.platform.dto.ruleset import Modality

if TYPE_CHECKING:
    import onnxruntime as ort

# A model tensor: float32 hidden states, features or logits.
type Float32Array = npt.NDArray[np.float32]

_MAX_LENGTH = 128
_HIDDEN = 384
_N_TAGS = 7
# The charge graph's outputs and the span graph's outputs, by name.
CHARGE_OUTPUTS = ("logits_charge", "logits_modality")
SPAN_OUTPUTS = ("logits_subject", "logits_target", "logits_action", "logits_scope")
# Axis-name aliases: a graph output name mapped to its neutral 5-tuple name
# (rename, not reorder).
_MULTISLOT_RENAME = {"logits_target": "logits_object", "logits_action": "logits_predicate"}
# Per-word class order (argmax): the labels in the order the decoder reads its outputs.
_MODALITY_LABELS: tuple[Modality, ...] = get_args(Modality)


# Tag order fixed by the bundled model.
_O, _B_DIR, _I_DIR, _B_REST, _I_REST, _B_NEUT, _I_NEUT = range(_N_TAGS)
_B_TAGS = (_B_DIR, _B_REST, _B_NEUT)
# The head's label for a run of tagged words.
type HeadClass = Literal["DIRECTIVE", "RESTRICTIVE", "NEUTRAL"]
# span class per (B, I) pair → head label
_TAG_CLASS: dict[int, HeadClass] = {
    _B_DIR: "DIRECTIVE",
    _I_DIR: "DIRECTIVE",
    _B_REST: "RESTRICTIVE",
    _I_REST: "RESTRICTIVE",
    _B_NEUT: "NEUTRAL",
    _I_NEUT: "NEUTRAL",
}


class _BioEncoder(_OnnxEncoderSession):
    """Bundled ONNX encoder returning per-token last-hidden-state + char offsets."""

    def __init__(self, onnx_path: Path) -> None:
        tokenizer_path = get_models_path() / EMBEDDER_SUBDIR / "tokenizer.json"
        if not onnx_path.is_file():
            raise RuntimeError(f"bundled ONNX encoder not found at {onnx_path}")
        if not tokenizer_path.is_file():
            raise RuntimeError(f"bundled tokenizer not found at {tokenizer_path}")
        self._init_session(onnx_path, tokenizer_path, _MAX_LENGTH)

    def forward_bucket(self, bucket: list[str]) -> list[tuple[Float32Array, list[tuple[int, int]]]]:
        """One forward over a bucket of texts → per-text ``(hidden [seq, hidden], offsets)``, padding trimmed."""
        tokens = self.tokenize(bucket)
        hidden = self._session.run(["last_hidden_state"], self.encode_feed(tokens))[0]  # (B, max_len, hidden)
        return [(hidden[i, : len(t.ids)], t.offsets) for i, t in enumerate(tokens)]


@lru_cache(maxsize=4)
def _head_session(head_path: str) -> ort.InferenceSession:
    return reload_after_repair(lambda: _build_head_session(head_path))


def _build_head_session(head_path: str) -> ort.InferenceSession:
    import onnxruntime as ort  # pylint: disable=import-outside-toplevel  # ML runtime loads on first model use

    opts = ort.SessionOptions()
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    # Coordinate intra-op with the encode thread pool: an explicit
    # AILS_ORT_THREADS wins (shard workers pin it to 1); otherwise intra-op is 1
    # when the pool is on and cpu_count when it is off, so pool * intra ~= cores.
    opts.intra_op_num_threads = ort_intra_threads()
    opts.inter_op_num_threads = 1
    return ort.InferenceSession(head_path, sess_options=opts, providers=["CPUExecutionProvider"])


def _pool_words(
    hidden: Float32Array, offsets: list[tuple[int, int]], text: str
) -> tuple[Float32Array, list[tuple[int, int]], list[bool]]:
    """Pool token hidden states into per-word means (fp32) from a precomputed forward.

    Returns ``(feats [n_words, hidden], word_spans, covered)``. A word with no token
    whose offset start lies inside it falls back to the mean of all content tokens —
    ``covered[i]`` is ``False`` for that word, the tokenizer's ``max_length`` truncation
    (:data:`_MAX_LENGTH`) having cut it out of the forward pass entirely; the fallback
    vector carries no signal specific to that word, and ``covered`` is read to keep an
    uninformative word from extending a decoded run.
    """
    content = [(i, s, e) for i, (s, e) in enumerate(offsets) if not (s == 0 and e == 0)]
    all_mean = hidden.mean(0)  # fallback contract: mean over ALL token states (incl. specials)
    word_spans = word_offsets(text)
    feats = []
    covered = []
    for ws, we in word_spans:
        idx = [i for i, s, _ in content if ws <= s < we]
        feats.append(hidden[idx].mean(0) if idx else all_mean)
        covered.append(bool(idx))
    if not feats:
        return np.empty((0, _HIDDEN), dtype=np.float32), [], []
    return np.stack(feats).astype(np.float32), word_spans, covered


# ──────────────────────────────────────────────────────────────────
# MULTI-SLOT 5-TUPLE PATH (reached only via multislot_available())
# ──────────────────────────────────────────────────────────────────

_SPAN_O, _SPAN_B, _SPAN_I = 0, 1, 2
_POLARITY: dict[HeadClass, int] = {"DIRECTIVE": 1, "RESTRICTIVE": -1, "NEUTRAL": 0}
_SOAS_AXES = ("subject", "predicate", "object", "scope")


@dataclass
class Span:
    """One decoded O/B/I span: its joined text, confidence, and token offset.

    ``conf`` is the mean max-softmax probability over the span's words, ``0.0``
    when the axis decodes no span (``text`` empty). ``offset`` is the
    ``[start_tok, end_tok)`` half-open word-index bounding box covering every
    B/I run folded into ``text`` (start inclusive, end exclusive — mirrors the
    half-open char offsets ``word_spans`` already uses); ``None`` when the axis
    decodes no span.
    """

    text: str
    conf: float
    offset: tuple[int, int] | None = None


@dataclass
class AtomTuple:
    """A per-sentence 5-tuple: polarity + subject/predicate/object/scope spans.

    The four spans are separated: ``subject`` is the actor (who performs / is
    governed; empty for imperatives), ``predicate`` the action, ``object`` the
    value only (subject is no longer fused into it), ``scope`` the condition.
    Each is a :class:`Span` carrying its own text and confidence.
    """

    polarity: int  # +1 directive, -1 restrictive, 0 neutral
    modality: Modality
    subject: Span
    predicate: Span
    object: Span
    scope: Span
    text: str


@lru_cache(maxsize=1)
def _enc_a() -> _BioEncoder:
    return reload_after_repair(lambda: _BioEncoder(_enc_a_path()))


@lru_cache(maxsize=1)
def _enc_b() -> _BioEncoder:
    return reload_after_repair(lambda: _BioEncoder(_enc_b_path()))


def _softmax_rows(logits: Float32Array) -> Float32Array:
    """Row-wise softmax over the last axis."""
    e = np.exp(logits - logits.max(axis=-1, keepdims=True))
    probs: Float32Array = (e / e.sum(axis=-1, keepdims=True)).astype(np.float32)
    return probs


def _run_head(
    feats: Float32Array, word_spans: list[tuple[int, int]], head_path: Path, outputs: Sequence[str]
) -> tuple[dict[str, Float32Array], list[tuple[int, int]]]:
    """Run the (small) head over pooled word features → ({output_name: logits}, word_spans)."""
    if feats.shape[0] == 0:
        return {}, word_spans
    session = _head_session(str(head_path))
    feed: dict[str, Float32Array] = {"word_feats": feats[None, :, :]}
    if any(i.name == "word_mask" for i in session.get_inputs()):
        feed["word_mask"] = np.ones((1, feats.shape[0]), dtype=np.float32)
    raw = session.run(list(outputs), feed)
    return dict(zip(outputs, raw, strict=True)), word_spans


def _extract_pass_from_states(
    hidden: Float32Array, offsets: list[tuple[int, int]], text: str, head_path: Path, outputs: Sequence[str]
) -> tuple[dict[str, Float32Array], list[tuple[int, int]], list[bool]]:
    """Head extraction from a precomputed encoder forward — the batched path's per-text step."""
    feats, word_spans, covered = _pool_words(hidden, offsets, text)
    out, word_spans = _run_head(feats, word_spans, head_path, outputs)
    return out, word_spans, covered
