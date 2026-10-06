"""Multi-atom decode — the tagger segments a sentence into N atoms.

Each run of tagged words (one contiguous directive or prohibition) becomes one
atom: the run's class is the atom's charge, and each axis span is assigned to
the atom whose extent contains it with its offset rebased to index the atom's
own text.

A run's OWN tagged word extent almost never covers the whole unit — the words
the head left untagged (``O``) between and around runs carry no atom of their
own, so a run's text is WIDENED to butt against its neighbours before it
becomes an atom's text (:func:`_widen_runs_to_cover`): every word in the unit
ends up inside exactly one atom, none silently dropped.

Split out of ``bio_tagger`` (which keeps the model session handles and the
shared decode primitives this module imports).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from reporails_cli.core.mapper.bio_graphs import _head_a_path, _head_b_path
from reporails_cli.core.mapper.bio_tagger import (
    _B_NEUT,
    _B_TAGS,
    _I_NEUT,
    _MODALITY_LABELS,
    _MULTISLOT_RENAME,
    _O,
    _POLARITY,
    _SOAS_AXES,
    _SPAN_B,
    _SPAN_I,
    _TAG_CLASS,
    AtomTuple,
    Span,
    _enc_a,
    _enc_b,
    _extract_pass,
    _extract_pass_from_states,
    _head_session,
    _softmax_rows,
)
from reporails_cli.core.mapper.onnx_session import _Tokens

_BUCKET_SIZE = 32
_CHARGE_OUT = ["logits_charge", "logits_modality"]
_SPAN_OUT = ["logits_subject", "logits_target", "logits_action", "logits_scope"]


def _decode_span_axis_runs(logits: Any, word_spans: list[tuple[int, int]], text: str) -> list[Span]:
    """O/B/I decode of a ``[n_words, 3]`` span axis → one :class:`Span` per disjoint B-run.

    Keeps the runs separate (sentence order) — the multiplicity a compound carries.
    ``[]`` when no B fires.
    """
    max_probs = _softmax_rows(logits).max(axis=1)
    tags = logits.argmax(axis=1)
    runs: list[Span] = []
    start: int | None = None
    acc: list[float] = []

    def _close(end_w: int) -> None:
        if start is not None and acc:
            runs.append(
                Span(text[word_spans[start][0] : word_spans[end_w][1]], sum(acc) / len(acc), (start, end_w + 1))
            )

    for w, tag in enumerate(tags):
        if tag == _SPAN_B:
            _close(w - 1)
            start, acc = w, [float(max_probs[w])]
        elif tag == _SPAN_I and start is not None:
            acc.append(float(max_probs[w]))
        else:
            _close(w - 1)
            start, acc = None, []
    _close(len(tags) - 1)
    return runs


def _charge_runs(
    logits_charge: Any, logits_modality: Any, covered: list[bool] | None = None
) -> list[tuple[int, int, str, str, float]]:
    """Argmax the charge tags into per-atom runs — each B-run is one atom.

    Only a B-tag opens a run (its class is the run's charge); an I-tag extends the
    open run, its own class ignored as within-run noise (the BIO transition-smoothing
    the reference decode assumes); O ends the run. Pure argmax, no threshold. Returns
    ``(word_start, word_end_exclusive, charge_class, modality, mean_conf)`` per run.

    ``covered`` (from :func:`bio_tagger._pool_words`) flags a word with no real token
    behind it — past the encoder's ``max_length`` truncation, so its logits come from
    the whole-text fallback vector, not that word's own content. Such a word cannot be
    trusted to extend or open a signed run; it is forced into a standalone NEUTRAL run
    instead of silently riding an open ``+1``/``-1`` run to a false sign.
    """
    tags = logits_charge.argmax(axis=1)
    mod_idx = logits_modality.argmax(axis=1)
    probs = _softmax_rows(logits_charge).max(axis=1)
    runs: list[tuple[int, int, str, str, float]] = []
    cur: str | None = None
    start = 0
    acc: list[float] = []

    def _close(end_w: int) -> None:
        if cur is not None and acc:
            runs.append((start, end_w + 1, cur, _MODALITY_LABELS[int(mod_idx[start])], sum(acc) / len(acc)))

    for w, tag in enumerate(tags):
        ti = int(tag)
        if covered is not None and not covered[w]:
            # No real token signal for this word — force it into its own NEUTRAL
            # run rather than trust the fallback-vector logits' class.
            ti = _B_NEUT if cur != "NEUTRAL" else _I_NEUT
        if ti == _O:
            _close(w - 1)
            cur, acc = None, []
        elif ti in _B_TAGS or cur is None:  # a B (or an orphan leading I) opens a run
            _close(w - 1)
            cur, start, acc = _TAG_CLASS[ti], w, [float(probs[w])]
        else:  # an I-tag extends the open run; a class-flipped I is within-run noise
            acc.append(float(probs[w]))
    _close(len(tags) - 1)
    return runs


def _widen_runs_to_cover(
    runs: list[tuple[int, int, str, str, float]], n_words: int
) -> list[tuple[int, int, str, str, float]]:
    """Widen each surviving charge run so consecutive runs partition ``[0, n_words)`` with no gap.

    A charge run's own word extent is only the words the head actually tagged
    B/I; every word in between and around runs is ``O`` and belongs to no run at
    all. Leading ``O`` words before the first run join it; interior ``O`` words
    between two runs and trailing ``O`` words after the last run join the
    PRECEDING run. Only the widened text span changes — start/end word indices —
    the run's charge class, modality, and confidence are untouched, so the
    number of atoms and their signs are exactly what :func:`_charge_runs` decoded.
    """
    widened: list[tuple[int, int, str, str, float]] = []
    for i, (cs, _ce, cls, mod, conf) in enumerate(runs):
        new_cs = 0 if i == 0 else cs
        new_ce = runs[i + 1][0] if i + 1 < len(runs) else n_words
        widened.append((new_cs, new_ce, cls, mod, conf))
    return widened


def _acts(run: tuple[int, int, str, str, float], predicate_runs: list[Span]) -> bool:
    """Whether a run's words hold a decoded action (a predicate span overlaps it)."""
    return any(p.offset is not None and p.offset[0] < run[1] and p.offset[1] > run[0] for p in predicate_runs)


def _fold_back(folded: list[tuple[int, int, str, str, float]], run: tuple[int, int, str, str, float]) -> None:
    """Join ``run`` onto the run before it when both carry the same sign, else keep it apart."""
    if folded and _POLARITY[folded[-1][2]] == _POLARITY[run[2]]:
        folded[-1] = (folded[-1][0], run[1], *folded[-1][2:])
    else:
        folded.append(run)


def _fold_actionless_runs(
    runs: list[tuple[int, int, str, str, float]], predicate_runs: list[Span]
) -> list[tuple[int, int, str, str, float]]:
    """Fold a charged run that decodes no action — a joining word (`Or`), a bare subject — into the run of
    the same sign beside it: the one after it, else the one before it. The joined run keeps the charge of
    the run that holds the action. A neutral run, and a run whose neighbours carry the other sign, stay apart.
    """
    folded: list[tuple[int, int, str, str, float]] = []
    pending: tuple[int, int, str, str, float] | None = None
    for run in runs:
        if pending is not None:
            if _POLARITY[run[2]] == _POLARITY[pending[2]]:
                run = (pending[0], *run[1:])
            else:
                _fold_back(folded, pending)
            pending = None
        if _POLARITY[run[2]] != 0 and not _acts(run, predicate_runs):
            pending = run
        else:
            folded.append(run)
    if pending is not None:
        _fold_back(folded, pending)
    return folded


def _assign_span(runs: list[Span], cs: int, ce: int, word_spans: list[tuple[int, int]], text: str) -> Span:
    """The atom's span for one axis: every axis run OVERLAPPING ``[cs, ce)``, clipped to it and joined.

    Clipping (not strict containment) keeps a run that straddles the charge-run
    boundary; joining every overlapping run (not just the top-confidence one) keeps
    both when an axis decodes two runs inside one atom — matching the whole-sentence
    join the single-tuple path does. Offset is rebased to the atom's own text; empty
    :class:`Span` when no run overlaps.
    """
    clipped = [
        (max(r.offset[0], cs), min(r.offset[1], ce), r.conf)
        for r in runs
        if r.offset is not None and r.offset[0] < ce and r.offset[1] > cs
    ]
    if not clipped:
        return Span("", 0.0, None)
    lo = min(c[0] for c in clipped)
    hi = max(c[1] for c in clipped)
    conf = sum(c[2] for c in clipped) / len(clipped)
    return Span(text[word_spans[lo][0] : word_spans[hi - 1][1]], conf, (lo - cs, hi - cs))


def _atom_from_charge_run(
    run: tuple[int, int, str, str, float],
    axis_runs: dict[str, list[Span]],
    word_spans: list[tuple[int, int]],
    text: str,
    n: int,
) -> AtomTuple:
    """One atom from a (widened) charge run: text = the run's covered extent, spans = the axis runs it contains."""
    cs, ce, cls, modality, _ = run
    atom_text = text[word_spans[cs][0] : word_spans[ce - 1][1]]
    mod = "none" if cls == "NEUTRAL" else (modality if modality != "none" else "direct")
    sp = {axis: _assign_span(axis_runs[axis], cs, ce, word_spans, text) for axis in _SOAS_AXES}
    return AtomTuple(
        _POLARITY[cls], mod, sp["subject"], sp["predicate"], sp["object"], sp["scope"], 0.0, n > 1, atom_text
    )


_Decoded = tuple[dict[str, Any], list[tuple[int, int]], list[bool]]


def _neutral_tuple(text: str) -> AtomTuple:
    empty = Span("", 0.0)
    return AtomTuple(0, "none", empty, empty, empty, empty, 0.0, False, text)


def _merge(out: dict[str, Any] | None, out_b: dict[str, Any] | None) -> dict[str, Any] | None:
    """Merge the span pass's aliased logits into the charge pass; ``None`` if either is empty."""
    if not out or not out_b:
        return None
    out.update({_MULTISLOT_RENAME.get(name, name): val for name, val in out_b.items()})
    return out


def _decode_logits(text: str) -> _Decoded | None:
    """Run both classification passes (per-text) and merge their aliased logits.

    ``covered`` comes from the first pass — it is what :func:`_charge_runs`
    reads to keep a past-truncation word from extending a signed run on a
    fallback-vector guess.
    """
    out, word_spans, covered = _extract_pass(text, _enc_a(), _head_a_path(), _CHARGE_OUT)
    out_b, _, _ = _extract_pass(text, _enc_b(), _head_b_path(), _SPAN_OUT)
    merged = _merge(out, out_b)
    return (merged, word_spans, covered) if merged is not None else None


def _decode_logits_batch(texts: list[str], progress: Callable[[int, int], None] | None = None) -> list[_Decoded | None]:
    """Batched :func:`_decode_logits`: each distinct text is decoded once, one pool task per bucket.

    ``progress(done, total)`` counts distinct texts and is called from the calling
    thread. Results equal the per-text path for every input position.
    """
    if not texts:
        return []
    from reporails_cli.core.mapper.encode_pool import run_buckets

    enc_a, enc_b = _enc_a(), _enc_b()
    head_a, head_b = _head_a_path(), _head_b_path()
    _head_session(str(head_a))
    _head_session(str(head_b))
    buckets, slot = enc_a.plan_buckets(texts, _BUCKET_SIZE)

    def _task(bucket: list[_Tokens]) -> Callable[[], list[_Decoded | None]]:
        def run() -> list[_Decoded | None]:
            decoded: list[_Decoded | None] = []
            for tok, (ha, oa), (hb, ob) in zip(
                bucket, enc_a.forward_bucket(bucket), enc_b.forward_bucket(bucket), strict=True
            ):
                out, word_spans, covered = _extract_pass_from_states(ha, oa, tok.text, head_a, _CHARGE_OUT)
                out_b, _, _ = _extract_pass_from_states(hb, ob, tok.text, head_b, _SPAN_OUT)
                merged = _merge(out, out_b)
                decoded.append((merged, word_spans, covered) if merged is not None else None)
            return decoded

        return run

    total = sum(len(b) for b in buckets)
    finished = 0

    def _done(i: int) -> None:
        nonlocal finished
        finished += len(buckets[i])
        if progress is not None:
            progress(finished, total)

    flat = [d for part in run_buckets([_task(b) for b in buckets], _done) for d in part]
    return [flat[i] for i in slot]


def _frames_from_decoded(decoded: _Decoded | None, text: str) -> list[AtomTuple]:
    """Charge-run segmentation of one sentence's decoded logits → N frame-atoms.

    Runs are widened to cover every word of ``text`` (:func:`_widen_runs_to_cover`)
    after the alphanumeric filter, so a dropped punctuation-only run's word range
    folds into its preceding neighbour rather than reopening a gap. A charged run that
    decodes no action then folds into its neighbour (:func:`_fold_actionless_runs`).
    """
    if decoded is None:
        return [_neutral_tuple(text)]
    out, word_spans, covered = decoded
    runs = [
        r
        for r in _charge_runs(out["logits_charge"], out["logits_modality"], covered)
        if any(ch.isalnum() for ch in text[word_spans[r[0]][0] : word_spans[r[1] - 1][1]])
    ]
    if not runs:  # no run with alphanumeric content — one neutral atom, never a punctuation-only atom
        return [_neutral_tuple(text)]
    runs = _widen_runs_to_cover(runs, len(word_spans))
    axis_runs = {axis: _decode_span_axis_runs(out[f"logits_{axis}"], word_spans, text) for axis in _SOAS_AXES}
    runs = _fold_actionless_runs(runs, axis_runs["predicate"])
    return [_atom_from_charge_run(r, axis_runs, word_spans, text, len(runs)) for r in runs]


def _heading_tuple_from_decoded(decoded: _Decoded | None, text: str) -> AtomTuple:
    """Collapse one heading's decoded logits to a single atom (dominant charge run).

    Picks the highest-CONFIDENCE run over all runs (signed or neutral). A "strongest signed
    run wins" rule over-charges a confidently-neutral heading that carries a weak spurious
    signed span (`## Notes: things to do later`); routing that on confidence keeps the
    confident-neutral read. A confidence-aware signed-preference is deferred.
    """
    if decoded is None:
        return _neutral_tuple(text)
    out, word_spans, covered = decoded
    runs = _charge_runs(out["logits_charge"], out["logits_modality"], covered)
    dom = max(runs, key=lambda r: r[4]) if runs else None
    cls, modality = (dom[2], dom[3]) if dom else ("NEUTRAL", "none")
    mod = "none" if cls == "NEUTRAL" else (modality if modality != "none" else "direct")
    n = len(word_spans)
    sp = {
        axis: _assign_span(_decode_span_axis_runs(out[f"logits_{axis}"], word_spans, text), 0, n, word_spans, text)
        for axis in _SOAS_AXES
    }
    return AtomTuple(_POLARITY[cls], mod, sp["subject"], sp["predicate"], sp["object"], sp["scope"], 0.0, False, text)


def tag_atom_multislot_frames(text: str) -> list[AtomTuple]:
    """Decode one sentence into N atoms via charge-run segmentation.

    The charge BIO tags argmax-decode into runs — each run is one atom, its
    word extent the atom's text, its class the atom's charge. Each axis span is
    assigned to the atom whose extent contains it, its offset rebased to the
    atom's own text. Pure argmax, no threshold.
    """
    return _frames_from_decoded(_decode_logits(text), text)


def tag_heading_multislot(text: str) -> AtomTuple:
    """Decode a heading as ONE atom via the same argmax/no-threshold path (dominant charge run)."""
    return _heading_tuple_from_decoded(_decode_logits(text), text)


def tag_atoms_multislot_frames_batch(texts: list[str]) -> list[list[AtomTuple]]:
    """Batched :func:`tag_atom_multislot_frames` — one encoder forward per encoder for the batch."""
    return [_frames_from_decoded(dec, t) for t, dec in zip(texts, _decode_logits_batch(texts), strict=True)]


def tag_headings_multislot_batch(texts: list[str]) -> list[AtomTuple]:
    """Batched :func:`tag_heading_multislot`."""
    return [_heading_tuple_from_decoded(dec, t) for t, dec in zip(texts, _decode_logits_batch(texts), strict=True)]
