"""Span tagger for running text.

Takes one line of text and returns its spans, each with a charge sign, a
modality, and a confidence. Word-pooling, log-softmax, and the Viterbi decode
run in numpy, torch-free. Callers guard on :func:`multislot_available`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from reporails_cli.core.mapper.bio_graphs import (
    _enc_a_path,
    _enc_b_path,
    _graph_content_hash,
    _head_a_path,
    _head_b_path,
)
from reporails_cli.core.mapper.onnx_session import _OnnxEncoderSession

_MAX_LENGTH = 128
_HIDDEN = 384
_N_TAGS = 7
_MODEL_SUBDIR = "minilm-l6-v2"
# Axis-name aliases: a graph output name mapped to its neutral 5-tuple name
# (rename, not reorder).
_MULTISLOT_RENAME = {"logits_target": "logits_object", "logits_action": "logits_predicate"}
# Per-word class order (argmax); fixed by the bundled artifact.
_MODALITY_LABELS = ("imperative", "direct", "absolute", "hedged", "none")


# Tag order fixed by the bundled model.
_O, _B_DIR, _I_DIR, _B_REST, _I_REST, _B_NEUT, _I_NEUT = range(_N_TAGS)
_B_TAGS = (_B_DIR, _B_REST, _B_NEUT)
_I_TAGS = (_I_DIR, _I_REST, _I_NEUT)
# span class per (B, I) pair → head label
_TAG_CLASS = {
    _B_DIR: "DIRECTIVE",
    _I_DIR: "DIRECTIVE",
    _B_REST: "RESTRICTIVE",
    _I_REST: "RESTRICTIVE",
    _B_NEUT: "NEUTRAL",
    _I_NEUT: "NEUTRAL",
}
# I-tag → its only legal predecessors (B-X or I-X of the same class).
_I_PREV = {_I_DIR: (_B_DIR, _I_DIR), _I_REST: (_B_REST, _I_REST), _I_NEUT: (_B_NEUT, _I_NEUT)}

_WORD_RE = re.compile(r"\S+")


def word_offsets(text: str) -> list[tuple[int, int]]:
    """Character offsets of each word in `text` — the word coordinates an atom's slot spans use."""
    return [(m.start(), m.end()) for m in _WORD_RE.finditer(text)]


def words_between(text: str, start: int, end: int) -> str:
    """`text` over words `[start, end)`; empty when the span falls outside the text."""
    words = word_offsets(text)
    if not 0 <= start < end <= len(words):
        return ""
    return text[words[start][0] : words[end - 1][1]]


DEFAULT_TAU = 0.6
# A decoded span is kept only when its mean per-word confidence clears this value.
SPAN_TAU = 0.7


@dataclass
class BioSpan:
    """A decoded span: text, head charge label, confidence, abstention flag, modality."""

    text: str
    charge: str  # DIRECTIVE | RESTRICTIVE | NEUTRAL
    confidence: float
    abstained: bool
    modality: str = "none"  # imperative | direct | absolute | hedged | none


def multislot_fingerprint() -> str:
    """Cache-identity token for the classification models this module loads.

    Returns a content hash (see `_graph_content_hash`) over the bundled model
    files this module reads, so any change to those files invalidates the
    per-file atom cache and the whole-map identity cache. The hash itself is
    memoized on disk (`bio_graphs._graph_content_hash`), so a repeat process
    pays no re-hash for an unchanged install. Returns ``"none"`` when a
    required file is missing.
    """
    from reporails_cli.bundled import get_models_path

    paths = (
        _enc_a_path(),
        _head_a_path(),
        _enc_b_path(),
        _head_b_path(),
        get_models_path() / _MODEL_SUBDIR / "onnx" / "model.onnx",
        get_models_path() / _MODEL_SUBDIR / "tokenizer.json",
    )
    parts = []
    for path in paths:
        if not path.is_file():
            return "none"
        parts.append(_graph_content_hash(path))
    return "|".join(parts)


class _BioEncoder(_OnnxEncoderSession):
    """Bundled ONNX encoder returning per-token last-hidden-state + char offsets."""

    def __init__(self, onnx_path: Path) -> None:
        from reporails_cli.bundled import get_models_path

        tokenizer_path = get_models_path() / _MODEL_SUBDIR / "tokenizer.json"
        if not onnx_path.is_file():
            raise RuntimeError(f"bundled ONNX encoder not found at {onnx_path}")
        if not tokenizer_path.is_file():
            raise RuntimeError(f"bundled tokenizer not found at {tokenizer_path}")
        self._init_session(onnx_path, tokenizer_path, _MAX_LENGTH)

    def token_states(self, text: str) -> tuple[Any, list[tuple[int, int]]]:
        """Encode ``text`` → ``(last_hidden_state [seq, hidden], per-token char offsets)``."""
        import numpy as np

        enc = self._tokenizer.encode(text)
        ids = np.array([enc.ids], dtype=np.int64)
        masks = np.array([enc.attention_mask], dtype=np.int64)
        feed: dict[str, Any] = {"input_ids": ids, "attention_mask": masks}
        if self._needs_token_type_ids:
            feed["token_type_ids"] = np.zeros_like(ids)
        last_hidden = self._session.run(["last_hidden_state"], feed)[0][0]  # (seq, hidden)
        return last_hidden, list(enc.offsets)

    def forward_bucket(self, bucket: list[str]) -> list[tuple[Any, list[tuple[int, int]]]]:
        """One forward over a bucket of texts → per-text ``(hidden [seq, hidden], offsets)``, padding trimmed."""
        tokens = self._tokenize(bucket)
        hidden = self._session.run(["last_hidden_state"], self._encode_feed(tokens))[0]  # (B, max_len, hidden)
        return [(hidden[i, : len(t.ids)], t.offsets) for i, t in enumerate(tokens)]


@lru_cache(maxsize=4)
def _head_session(head_path: str) -> Any:
    from reporails_cli.bundled import reload_after_repair

    return reload_after_repair(lambda: _build_head_session(head_path))


def _build_head_session(head_path: str) -> Any:
    import onnxruntime as ort

    opts = ort.SessionOptions()
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    # Coordinate intra-op with the encode thread pool: an explicit
    # AILS_ORT_THREADS wins (shard workers pin it to 1); otherwise intra-op is 1
    # when the pool is on and cpu_count when it is off, so pool * intra ~= cores.
    from reporails_cli.core.mapper.encode_pool import ort_intra_threads

    opts.intra_op_num_threads = ort_intra_threads()
    opts.inter_op_num_threads = 1
    return ort.InferenceSession(head_path, sess_options=opts, providers=["CPUExecutionProvider"])


@lru_cache(maxsize=1)
def _transition() -> Any:
    """Transition score matrix ``T[prev, cur]`` for the tag decode."""
    import numpy as np

    t = np.zeros((_N_TAGS, _N_TAGS), dtype=np.float32)
    for cur in _I_TAGS:
        legal = set(_I_PREV[cur])
        for prev in range(_N_TAGS):
            if prev not in legal:
                t[prev, cur] = -1e4
    for prev in range(1, _N_TAGS):
        for cur in _B_TAGS:
            t[prev, cur] += -1.0
    return t


def _log_softmax(logits: Any) -> Any:
    """Numpy log-softmax over the last axis of ``[n_words, 7]`` logits."""
    import numpy as np

    shifted = logits - logits.max(axis=-1, keepdims=True)
    return shifted - np.log(np.exp(shifted).sum(axis=-1, keepdims=True))


def _pool_words(
    hidden: Any, offsets: list[tuple[int, int]], text: str
) -> tuple[Any, list[tuple[int, int]], list[bool]]:
    """Pool token hidden states into per-word means (fp32) from a precomputed forward.

    Returns ``(feats [n_words, hidden], word_spans, covered)``. A word with no token
    whose offset start lies inside it falls back to the mean of all content tokens —
    ``covered[i]`` is ``False`` for that word, the tokenizer's ``max_length`` truncation
    (:data:`_MAX_LENGTH`) having cut it out of the forward pass entirely; the fallback
    vector carries no signal specific to that word, and ``covered`` is read to keep an
    uninformative word from extending a decoded run.
    """
    import numpy as np

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


def _word_features(text: str, encoder: _BioEncoder) -> tuple[Any, list[tuple[int, int]], list[bool]]:
    """Encode ``text`` → per-word mean of token hidden states (fp32). ``encoder`` selects the graph."""
    hidden, offsets = encoder.token_states(text)
    return _pool_words(hidden, offsets, text)


def _viterbi(emissions: Any) -> list[int]:
    """Viterbi over log-softmax ``emissions`` [n_words, 7] with the transition mask."""
    import numpy as np

    n = emissions.shape[0]
    t = _transition()
    dp = emissions[0].copy()
    dp[list(_I_TAGS)] = -1e4  # start forbids I-*
    back = np.zeros((n, _N_TAGS), dtype=np.int64)
    cols = np.arange(_N_TAGS)
    for i in range(1, n):
        scores = dp[:, None] + t  # [prev, cur]
        best_prev = scores.argmax(0)  # [cur]
        dp = scores[best_prev, cols] + emissions[i]
        back[i] = best_prev
    last = int(dp.argmax())
    tags = [last]
    for i in range(n - 1, 0, -1):
        last = int(back[i, last])
        tags.append(last)
    tags.reverse()
    return tags


def _spans_from_tags(
    tags: list[int], probs: list[float], mod_idx: Any, word_spans: list[tuple[int, int]], text: str
) -> list[tuple[str, str, float, str]]:
    """Group B/I runs into (span_text, head_charge, mean_prob, modality). O breaks a run.

    Modality is the span B-word's modality class (the head reads modality only on
    in-span words, so the O-word classes carry no signal).
    """
    out: list[tuple[str, str, float, str]] = []
    cur_cls: str | None = None
    start_w = 0
    acc: list[float] = []

    def _close(end_w: int) -> None:
        if cur_cls is None or not acc:
            return
        s = word_spans[start_w][0]
        e = word_spans[end_w][1]
        modality = _MODALITY_LABELS[int(mod_idx[start_w])]
        out.append((text[s:e], cur_cls, sum(acc) / len(acc), modality))

    for w, tag in enumerate(tags):
        if tag == _O:
            _close(w - 1)
            cur_cls, acc = None, []
            continue
        cls = _TAG_CLASS[tag]
        is_begin = tag in _B_TAGS
        if is_begin or cls != cur_cls:
            _close(w - 1)
            cur_cls, start_w, acc = cls, w, [probs[w]]
        else:
            acc.append(probs[w])
    _close(len(tags) - 1)
    return out


def _finalize_spans(raw: list[tuple[str, str, float, str]], tau: float) -> list[BioSpan]:
    """Apply the abstention gate: a span below ``tau`` is forced NEUTRAL + flagged.

    Modality is reconciled to the charge invariant: a neutral/abstained span carries
    ``none``; a charged span keeps the head's modality but never ``none`` (a charged
    atom with ``modality == none`` is a schema violation), falling back to ``direct``.
    """
    spans: list[BioSpan] = []
    for span_text, cls, conf, modality in raw:
        abstained = conf < tau
        charge = "NEUTRAL" if abstained else cls
        if charge == "NEUTRAL":
            mod = "none"
        elif modality == "none":
            mod = "direct"
        else:
            mod = modality
        spans.append(BioSpan(span_text, charge, conf, abstained, mod))
    return spans


# ──────────────────────────────────────────────────────────────────
# MULTI-SLOT 5-TUPLE PATH (reached only via multislot_available())
# ──────────────────────────────────────────────────────────────────

_SPAN_O, _SPAN_B, _SPAN_I = 0, 1, 2
_POLARITY = {"DIRECTIVE": 1, "RESTRICTIVE": -1, "NEUTRAL": 0}
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
    """A per-sentence 5-tuple: polarity + subject/predicate/object/scope spans + a compound review flag.

    The four spans are separated: ``subject`` is the actor (who performs / is
    governed; empty for imperatives), ``predicate`` the action, ``object`` the
    value only (subject is no longer fused into it), ``scope`` the condition.
    Each is a :class:`Span` carrying its own text and confidence.
    ``compound_candidate`` is a low-precision review annotation ("more than one
    charged atom in the sentence"), never a hard split.
    """

    polarity: int  # +1 directive, -1 restrictive, 0 neutral
    modality: str
    subject: Span
    predicate: Span
    object: Span
    scope: Span
    compound_prob: float
    compound_candidate: bool
    text: str


def multislot_available() -> bool:
    """True when onnxruntime + tokenizers import and all four model graphs exist."""
    import importlib.util

    have_libs = all(importlib.util.find_spec(m) is not None for m in ("onnxruntime", "tokenizers"))
    graphs = (_enc_a_path(), _head_a_path(), _enc_b_path(), _head_b_path())
    return have_libs and all(p.is_file() for p in graphs)


@lru_cache(maxsize=1)
def _enc_a() -> _BioEncoder:
    from reporails_cli.bundled import reload_after_repair

    return reload_after_repair(lambda: _BioEncoder(_enc_a_path()))


@lru_cache(maxsize=1)
def _enc_b() -> _BioEncoder:
    from reporails_cli.bundled import reload_after_repair

    return reload_after_repair(lambda: _BioEncoder(_enc_b_path()))


def _softmax_rows(logits: Any) -> Any:
    """Row-wise softmax over the last axis."""
    import numpy as np

    e = np.exp(logits - logits.max(axis=-1, keepdims=True))
    return e / e.sum(axis=-1, keepdims=True)


def _decode_span_axis(
    logits: Any, word_spans: list[tuple[int, int]], text: str
) -> tuple[str, float, tuple[int, int] | None]:
    """Greedy O/B/I decode of a ``[n_words, 3]`` span axis → (joined text, confidence, offset).

    Confidence is the mean max-softmax probability over the in-span (B/I) words,
    mirroring the charge axis's mean-prob; ``0.0`` when the axis decodes no span.
    ``offset`` is the ``[start_tok, end_tok)`` word-index bounding box spanning
    every B/I run folded into the joined text (the common case is a single run);
    ``None`` when the axis decodes no span.
    """
    max_probs = _softmax_rows(logits).max(axis=1)
    tags = logits.argmax(axis=1)
    parts: list[str] = []
    in_span: list[float] = []
    start: int | None = None
    bbox: tuple[int, int] | None = None

    def _close(end_w: int) -> None:
        nonlocal bbox
        if start is not None:
            parts.append(text[word_spans[start][0] : word_spans[end_w][1]])
            lo = start if bbox is None else min(bbox[0], start)
            hi = end_w + 1 if bbox is None else max(bbox[1], end_w + 1)
            bbox = (lo, hi)

    for w, tag in enumerate(tags):
        if tag == _SPAN_B:
            _close(w - 1)
            start = w
            in_span.append(float(max_probs[w]))
        elif tag == _SPAN_I and start is not None:
            in_span.append(float(max_probs[w]))
        else:
            _close(w - 1)
            start = None
    _close(len(tags) - 1)
    return " ".join(parts), (sum(in_span) / len(in_span) if in_span else 0.0), bbox


def _sentence_charge(spans: list[BioSpan]) -> tuple[int, str]:
    """Sentence ``(polarity, modality)`` from the strongest non-neutral charged span."""
    charged = [s for s in spans if s.charge != "NEUTRAL"]
    if not charged:
        return 0, "none"
    dom = max(charged, key=lambda s: s.confidence)
    return _POLARITY[dom.charge], dom.modality


def _sentence_charge_from_logits(
    logits_charge: Any, logits_modality: Any, word_spans: list[tuple[int, int]], text: str, tau: float
) -> tuple[int, str]:
    """Viterbi-decode the charge tags → sentence ``(polarity, modality)``."""
    import numpy as np

    emissions = _log_softmax(logits_charge)
    tags = _viterbi(emissions)
    probs = [float(np.exp(emissions[w, tags[w]])) for w in range(len(tags))]
    spans = _finalize_spans(_spans_from_tags(tags, probs, logits_modality.argmax(axis=1), word_spans, text), tau)
    return _sentence_charge(spans)


def _multislot_tuple(
    out: dict[str, Any],
    word_spans: list[tuple[int, int]],
    text: str,
    tau: float,
    span_tau: float,
    _compound_threshold: float,
) -> AtomTuple:
    """Assemble an :class:`AtomTuple` from the decoded logits in ``out``.

    ``out`` is keyed by the neutral axis names (after the sidecar aliasing), so the
    span axes read ``logits_object`` / ``logits_predicate``.

    Each span axis is kept only when its mean per-word confidence clears
    ``span_tau``, otherwise it is dropped to an empty span.
    """
    spans: dict[str, Span] = {}
    for axis in ("subject", "predicate", "object", "scope"):
        span_text, conf, offset = _decode_span_axis(out[f"logits_{axis}"], word_spans, text)
        spans[axis] = Span(span_text, conf, offset) if conf >= span_tau else Span("", 0.0, None)
    polarity, modality = _sentence_charge_from_logits(
        out["logits_charge"], out["logits_modality"], word_spans, text, tau
    )
    return AtomTuple(
        polarity=polarity,
        modality=modality,
        subject=spans["subject"],
        predicate=spans["predicate"],
        object=spans["object"],
        scope=spans["scope"],
        compound_prob=0.0,
        compound_candidate=False,
        text=text,
    )


def _run_head(
    feats: Any, word_spans: list[tuple[int, int]], head_path: Path, outputs: list[str]
) -> tuple[dict[str, Any], list[tuple[int, int]]]:
    """Run the (small) head over pooled word features → ({output_name: logits}, word_spans)."""
    import numpy as np

    if feats.shape[0] == 0:
        return {}, word_spans
    session = _head_session(str(head_path))
    feed: dict[str, Any] = {"word_feats": feats[None, :, :]}
    if any(i.name == "word_mask" for i in session.get_inputs()):
        feed["word_mask"] = np.ones((1, feats.shape[0]), dtype=np.float32)
    raw = session.run(outputs, feed)
    return dict(zip(outputs, raw, strict=True)), word_spans


def _extract_pass(
    text: str, encoder: _BioEncoder, head_path: Path, outputs: list[str]
) -> tuple[dict[str, Any], list[tuple[int, int]], list[bool]]:
    """One encoder→head extraction pass → ({output_name: logits}, word_spans, covered)."""
    feats, word_spans, covered = _word_features(text, encoder=encoder)
    out, word_spans = _run_head(feats, word_spans, head_path, outputs)
    return out, word_spans, covered


def _extract_pass_from_states(
    hidden: Any, offsets: list[tuple[int, int]], text: str, head_path: Path, outputs: list[str]
) -> tuple[dict[str, Any], list[tuple[int, int]], list[bool]]:
    """Head extraction from a precomputed encoder forward — the batched path's per-text step."""
    feats, word_spans, covered = _pool_words(hidden, offsets, text)
    out, word_spans = _run_head(feats, word_spans, head_path, outputs)
    return out, word_spans, covered


def tag_atom_multislot(
    text: str, tau: float = DEFAULT_TAU, span_tau: float = SPAN_TAU, compound_threshold: float = 0.5
) -> AtomTuple:
    """Decode one sentence into a 5-tuple atom via the multi-slot graphs.

    Runs the two extraction passes over one shared whitespace-word pooling and
    assembles the decoded axes into a tuple. Which pass yields which axes, and the
    axis-name aliases, are fixed by ``_MULTISLOT_RENAME`` above. ``span_tau`` gates
    the four span axes (see :func:`_multislot_tuple`); ``tau`` gates the charge axis.
    """
    out, word_spans, _covered = _extract_pass(text, _enc_a(), _head_a_path(), ["logits_charge", "logits_modality"])
    graph_b = ["logits_subject", "logits_target", "logits_action", "logits_scope"]
    out_b, _, _ = _extract_pass(text, _enc_b(), _head_b_path(), graph_b)
    if not out or not out_b:
        empty = Span("", 0.0)
        return AtomTuple(0, "none", empty, empty, empty, empty, 0.0, False, text)
    out.update({_MULTISLOT_RENAME.get(name, name): val for name, val in out_b.items()})
    return _multislot_tuple(out, word_spans, text, tau, span_tau, compound_threshold)
