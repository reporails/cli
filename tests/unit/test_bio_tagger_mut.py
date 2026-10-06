"""Mutation-kill tests for bio_tagger decode internals.

The span-decode helpers (`_spans_from_tags`, `_finalize_spans`,
`_decode_span_axis`, `_decode_span_axis_runs`, `_sentence_charge`,
`_multislot_tuple`) are pure numpy — they take hand-built tag/logit arrays and
return spans, so they are exercised here with synthetic inputs and NO ONNX
model. The availability/fingerprint gates are exercised via monkeypatch.

Each test feeds an input whose correct output a specific injected operator bug
would change, so the assertion reddens when that bug returns.
"""

from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pytest

from reporails_cli.core.mapper import bio_graphs, bio_tagger
from reporails_cli.core.mapper.bio_tagger import (
    _B_DIR,
    _I_DIR,
    BioSpan,
    Span,
    _decode_span_axis,
    _finalize_spans,
    _sentence_charge,
    _spans_from_tags,
)
from reporails_cli.core.mapper.multislot_frames import (
    _assign_span,
    _charge_runs,
    _decode_span_axis_runs,
)

_CHARGE_TAG = {"O": 0, "B-DIR": 1, "I-DIR": 2, "B-REST": 3, "I-REST": 4, "B-NEUT": 5, "I-NEUT": 6}


def _charge_logits(tag_names: list[str]) -> np.ndarray:
    """One-hot charge logits whose per-word argmax is exactly ``tag_names``."""
    arr = np.full((len(tag_names), 7), -5.0, dtype=np.float32)
    for i, t in enumerate(tag_names):
        arr[i, _CHARGE_TAG[t]] = 5.0
    return arr


def _mod_logits(n: int) -> np.ndarray:
    arr = np.full((n, 5), -5.0, dtype=np.float32)
    arr[:, 0] = 5.0  # imperative
    return arr


def _word_spans(text: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in re.finditer(r"\S+", text)]


# ── _spans_from_tags ────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_spans_from_tags_emits_a_decoded_span() -> None:
    """A B/I run must produce one span (kills `cur_cls is None` -> `is not None`)."""
    text = "foo bar"
    ws = _word_spans(text)
    out = _spans_from_tags([_B_DIR, _I_DIR], [0.9, 0.9], np.array([1, 1]), ws, text)
    assert len(out) == 1
    assert out[0][0] == "foo bar"
    assert out[0][1] == "DIRECTIVE"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_spans_from_tags_two_begins_are_two_spans() -> None:
    """B B of the same class start two spans (kills `is_begin or ...` -> `and`)."""
    text = "foo bar"
    ws = _word_spans(text)
    out = _spans_from_tags([_B_DIR, _B_DIR], [0.9, 0.9], np.array([1, 1]), ws, text)
    assert len(out) == 2
    assert [s[0] for s in out] == ["foo", "bar"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_spans_from_tags_i_tag_continues_span() -> None:
    """B then I of same class stay one span (kills `cls != cur_cls` -> `==`)."""
    text = "foo bar"
    ws = _word_spans(text)
    out = _spans_from_tags([_B_DIR, _I_DIR], [0.9, 0.9], np.array([1, 1]), ws, text)
    assert len(out) == 1
    assert out[0][0] == "foo bar"


# ── _finalize_spans ─────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_finalize_charged_none_modality_falls_back_to_direct() -> None:
    """A charged span with modality 'none' must be lifted to 'direct'
    (kills `modality == "none"` -> `!=`)."""
    spans = _finalize_spans([("do it", "DIRECTIVE", 0.9, "none")], tau=0.6)
    assert len(spans) == 1
    assert spans[0].charge == "DIRECTIVE"
    assert spans[0].modality == "direct"


# ── _decode_span_axis ───────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_decode_span_axis_b_starts_span() -> None:
    """A B word must be captured (kills `tag == _SPAN_B` -> `!=`)."""
    text = "foo bar"
    ws = _word_spans(text)
    logits = np.array([[0.0, 5.0, 0.0], [5.0, 0.0, 0.0]])  # B, O
    span_text, conf, offset = _decode_span_axis(logits, ws, text)
    assert span_text == "foo"
    assert conf > 0.0
    assert offset == (0, 1)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_decode_span_axis_i_extends_span() -> None:
    """An I word must extend the B span (kills `tag == _SPAN_I` -> `!=`)."""
    text = "foo bar"
    ws = _word_spans(text)
    logits = np.array([[0.0, 5.0, 0.0], [0.0, 0.0, 5.0]])  # B, I
    span_text, _conf, offset = _decode_span_axis(logits, ws, text)
    assert span_text == "foo bar"
    assert offset == (0, 2)


# ── _sentence_charge ────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_sentence_charge_ignores_neutral_spans() -> None:
    """The charged filter keeps non-neutral spans (kills `!= "NEUTRAL"` -> `==`)."""
    spans = [
        BioSpan("a", "DIRECTIVE", 0.9, False, "direct"),
        BioSpan("b", "NEUTRAL", 0.5, False, "none"),
    ]
    assert _sentence_charge(spans) == (1, "direct")


# ── _decode_span_axis_runs ──────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_decode_runs_single_b_is_one_run() -> None:
    """A lone B word yields one run (kills `tag == _SPAN_B` -> `!=`)."""
    text = "foo"
    ws = _word_spans(text)
    logits = np.array([[0.0, 5.0, 0.0]])  # B
    runs = _decode_span_axis_runs(logits, ws, text)
    assert len(runs) == 1
    assert runs[0].text == "foo"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_decode_runs_i_extends_run() -> None:
    """B then I stay one run of two words (kills `tag == _SPAN_I` -> `!=`)."""
    text = "foo bar"
    ws = _word_spans(text)
    logits = np.array([[0.0, 5.0, 0.0], [0.0, 0.0, 5.0]])  # B, I
    runs = _decode_span_axis_runs(logits, ws, text)
    assert len(runs) == 1
    assert runs[0].text == "foo bar"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_decode_runs_o_breaks_run() -> None:
    """An O word must close the run, not extend it
    (kills `... and start is not None` -> `or`)."""
    text = "foo bar"
    ws = _word_spans(text)
    logits = np.array([[0.0, 5.0, 0.0], [5.0, 0.0, 0.0]])  # B, O
    runs = _decode_span_axis_runs(logits, ws, text)
    assert len(runs) == 1
    assert runs[0].text == "foo"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_decode_runs_two_disjoint_b_are_two_runs() -> None:
    """B O B decodes as TWO separate runs — the multiplicity the fan-out consumes."""
    text = "foo bar baz"
    ws = _word_spans(text)
    logits = np.array([[0.0, 5.0, 0.0], [5.0, 0.0, 0.0], [0.0, 5.0, 0.0]])  # B, O, B
    runs = _decode_span_axis_runs(logits, ws, text)
    assert [r.text for r in runs] == ["foo", "baz"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_decode_runs_carries_word_index_offset() -> None:
    """Each run carries its [start_tok, end_tok) word-index offset for the `so` wire."""
    text = "foo bar baz"
    ws = _word_spans(text)
    logits = np.array([[5.0, 0.0, 0.0], [0.0, 5.0, 0.0], [0.0, 0.0, 5.0]])  # O, B, I
    runs = _decode_span_axis_runs(logits, ws, text)
    assert len(runs) == 1
    assert runs[0].text == "bar baz"
    assert runs[0].offset == (1, 3)  # words 1..2 inclusive → half-open (1, 3)


# ── _charge_runs (charge-BIO atom segmentation) ──────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charge_runs_two_b_tags_are_two_atoms() -> None:
    """Each charge B-run is one atom: two B-tags → two runs with their own extent + class."""
    runs = _charge_runs(_charge_logits(["B-DIR", "I-DIR", "B-REST", "I-REST"]), _mod_logits(4))
    assert [(r[0], r[1], r[2]) for r in runs] == [(0, 2, "DIRECTIVE"), (2, 4, "RESTRICTIVE")]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charge_runs_class_flipped_i_does_not_split() -> None:
    """Only a B opens a run — a class-flipped I is within-run noise, not a new atom.

    Kills the `cls != cur` split bug: raw argmax emits noisy I-REST inside a DIRECTIVE
    run, and splitting on it over-segments (`the`/`linter.` as standalone atoms).
    """
    runs = _charge_runs(_charge_logits(["B-DIR", "I-REST", "I-DIR"]), _mod_logits(3))
    assert len(runs) == 1
    assert runs[0][:3] == (0, 3, "DIRECTIVE")


# ── _assign_span (span→atom overlap, clip, join + offset rebasing) ────

# words:  0    1    2    3       4       5
_SENT = "aa bb cc beta delta eek"
_SENT_WS = _word_spans(_SENT)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_assign_span_overlapping_run_rebased_to_atom_local() -> None:
    """A span overlapping the atom's extent is kept, offset rebased to atom-local words."""
    got = _assign_span([Span("beta", 0.9, (3, 4))], 2, 5, _SENT_WS, _SENT)  # atom extent [2,5)
    assert got.text == "beta"
    assert got.offset == (1, 2)  # 3-2, 4-2 — indexes the atom's own text


@pytest.mark.unit
@pytest.mark.subsys_map
def test_assign_span_joins_two_runs_inside_one_atom() -> None:
    """Two axis runs inside one atom are joined, not reduced to the top-confidence one.

    Kills the pick-one regression: dropping a same-atom run silently loses slot text.
    """
    got = _assign_span([Span("beta", 0.9, (3, 4)), Span("eek", 0.9, (5, 6))], 2, 6, _SENT_WS, _SENT)
    assert got.text == "beta delta eek"  # min-start..max-end slice
    assert got.offset == (1, 4)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_assign_span_straddling_run_is_clipped_not_dropped() -> None:
    """A run extending past the atom boundary is clipped in, not dropped (kills strict containment)."""
    got = _assign_span([Span("beta delta eek", 0.9, (3, 6))], 2, 5, _SENT_WS, _SENT)  # atom [2,5)
    assert got.text == "beta delta"  # clipped to the atom extent
    assert got.offset == (1, 3)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_assign_span_non_overlapping_run_is_empty() -> None:
    """A span not overlapping the atom's extent contributes nothing."""
    got = _assign_span([Span("eek", 0.9, (5, 6))], 0, 3, _SENT_WS, _SENT)
    assert got.text == "" and got.offset is None


# ── _multislot_tuple ────────────────────────────────────────────────


def _multislot_out(text: str) -> dict:
    """Build a decoded-logits dict for _multislot_tuple with an object span."""
    n = len(_word_spans(text))
    zeros7 = np.zeros((n, 7), dtype=np.float32)
    zeros5 = np.zeros((n, 5), dtype=np.float32)
    empty3 = np.tile(np.array([5.0, 0.0, 0.0], dtype=np.float32), (n, 1))  # all-O
    # object axis: first word B, rest I → a real span
    obj = empty3.copy()
    obj[0] = np.array([0.0, 5.0, 0.0], dtype=np.float32)
    for i in range(1, n):
        obj[i] = np.array([0.0, 0.0, 5.0], dtype=np.float32)
    return {
        "logits_subject": empty3.copy(),
        "logits_predicate": empty3.copy(),
        "logits_object": obj,
        "logits_scope": empty3.copy(),
        "logits_charge": zeros7,
        "logits_modality": zeros5,
    }


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_tuple_keeps_span_at_threshold() -> None:
    """A span whose confidence equals span_tau is kept (kills `>=` -> `>`)."""
    text = "foo bar"
    ws = _word_spans(text)
    out = _multislot_out(text)
    # Decode the object axis to learn its exact confidence, then gate AT it.
    _txt, conf, _offset = bio_tagger._decode_span_axis(out["logits_object"], ws, text)
    tup = bio_tagger._multislot_tuple(out, ws, text, tau=0.6, span_tau=conf, _compound_threshold=0.5)
    assert tup.object.text == "foo bar"
    assert tup.object.offset == (0, 2)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_tuple_compound_candidate_defaults_false() -> None:
    """The assembled tuple never flags compound (kills `compound_candidate=False` -> True)."""
    text = "foo bar"
    ws = _word_spans(text)
    out = _multislot_out(text)
    tup = bio_tagger._multislot_tuple(out, ws, text, tau=0.6, span_tau=0.9, _compound_threshold=0.5)
    assert tup.compound_candidate is False


# ── availability / fingerprint gates ────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_available_false_when_graph_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """One missing graph → not available (kills `and` -> `or` in multislot_available)."""
    monkeypatch.setattr(bio_tagger, "_enc_a_path", lambda: Path("/nonexistent/encA.onnx"))
    assert bio_tagger.multislot_available() is False


@pytest.mark.unit
@pytest.mark.subsys_map
def test_enc_a_repairs_cache_once_and_retries_after_a_corrupted_load(monkeypatch: pytest.MonkeyPatch) -> None:
    """REGRESSION: a same-size corrupted `charge_encoder_encA.onnx` must not
    crash every check forever with a raw ONNX-runtime traceback. `_enc_a()` repairs
    the persistent cache once (never the in-package dev tree) and retries the load."""
    import reporails_cli.bundled as bundled_mod
    from reporails_cli.core.mapper import model_fetch

    bio_tagger._enc_a.cache_clear()
    monkeypatch.setattr(bundled_mod, "_tree_present", False)
    monkeypatch.setattr(bundled_mod, "_repair_events", {})
    # tests/conftest.py defaults AILS_MODEL_OFFLINE=1 for the whole suite; this
    # test exercises the online repair path.
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)

    attempts = {"n": 0}

    def flaky_init(self: object, onnx_path: Path) -> None:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RuntimeError("simulated same-size corrupted ONNX load")
        self._session = object()  # type: ignore[attr-defined]
        self._tokenizer = object()  # type: ignore[attr-defined]
        self._needs_token_type_ids = False  # type: ignore[attr-defined]

    monkeypatch.setattr(bio_tagger._BioEncoder, "__init__", flaky_init)
    # The cache really is damaged in this scenario (a same-size corrupted
    # file); tell `reload_after_repair` so without touching a real cache dir.
    monkeypatch.setattr(model_fetch, "cache_damaged", lambda *a, **k: True)
    repaired = {"called": False}
    monkeypatch.setattr(model_fetch, "repair_cache", lambda *a, **k: repaired.update(called=True))

    try:
        encoder = bio_tagger._enc_a()
    finally:
        bio_tagger._enc_a.cache_clear()

    assert repaired["called"] is True
    assert attempts["n"] == 2  # one failing load, one repaired retry — never a third
    assert isinstance(encoder, bio_tagger._BioEncoder)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_enc_a_never_repairs_the_in_package_dev_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    """A load failure against the in-package dev tree (no pins apply there) must
    re-raise unchanged — a network repair could not fix a dev checkout's own files."""
    import reporails_cli.bundled as bundled_mod
    from reporails_cli.core.mapper import model_fetch

    bio_tagger._enc_a.cache_clear()
    monkeypatch.setattr(bundled_mod, "_tree_present", True)

    def always_fails(self: object, onnx_path: Path) -> None:
        raise RuntimeError("dev tree file is broken")

    monkeypatch.setattr(bio_tagger._BioEncoder, "__init__", always_fails)
    repaired = {"called": False}
    monkeypatch.setattr(model_fetch, "repair_cache", lambda *a, **k: repaired.update(called=True))

    try:
        with pytest.raises(RuntimeError, match="dev tree file is broken"):
            bio_tagger._enc_a()
    finally:
        bio_tagger._enc_a.cache_clear()

    assert repaired["called"] is False


# ── multislot_fingerprint: must fold ALL graphs, not just the two heads ──


def _seed_fake_model_dir(models_dir: Path) -> None:
    """Lay out the 6 files multislot_fingerprint reads, with cheap fake bytes.

    Mirrors the bundled layout (`bundled/models/`) without copying the real
    multi-hundred-MB weights — the fingerprint is a generic file hasher, so it
    exercises the same code path over small stand-in files.
    """
    (models_dir / "minilm-l6-v2" / "onnx").mkdir(parents=True)
    (models_dir / "charge_encoder_encA.onnx").write_bytes(b"encA-v1")
    (models_dir / "charge_encoder_encB.onnx").write_bytes(b"encB-v1")
    (models_dir / "multislot_head_encA.onnx").write_bytes(b"headA-v1")
    (models_dir / "multislot_head_encB.onnx").write_bytes(b"headB-v1")
    (models_dir / "minilm-l6-v2" / "onnx" / "model.onnx").write_bytes(b"embedder-v1")
    (models_dir / "minilm-l6-v2" / "tokenizer.json").write_text("{}")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_fingerprint_stable_with_no_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two calls with nothing changed must return the identical fingerprint."""
    import reporails_cli.bundled as bundled_mod

    fake_models = tmp_path / "models"
    _seed_fake_model_dir(fake_models)
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)

    fp1 = bio_tagger.multislot_fingerprint()
    fp2 = bio_tagger.multislot_fingerprint()
    assert fp1 == fp2


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_fingerprint_changes_when_charge_encoder_a_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Swapping the first encoder's weights (not just the heads) must
    re-key the fingerprint — this is what full_map_cache.compute_identity and
    pipeline._open_map_cache fold into their cache identity."""
    import reporails_cli.bundled as bundled_mod

    fake_models = tmp_path / "models"
    _seed_fake_model_dir(fake_models)
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)

    before = bio_tagger.multislot_fingerprint()
    (fake_models / "charge_encoder_encA.onnx").write_bytes(b"encA-v2-different-weights")
    after = bio_tagger.multislot_fingerprint()
    assert before != after


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_fingerprint_changes_when_charge_encoder_b_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same as the first encoder, mirrored for the second."""
    import reporails_cli.bundled as bundled_mod

    fake_models = tmp_path / "models"
    _seed_fake_model_dir(fake_models)
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)

    before = bio_tagger.multislot_fingerprint()
    (fake_models / "charge_encoder_encB.onnx").write_bytes(b"encB-v2-different-weights")
    after = bio_tagger.multislot_fingerprint()
    assert before != after


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_fingerprint_changes_when_tokenizer_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The bundled tokenizer changing (a model release that only touches
    `tokenizer.json`) must re-key too — otherwise a tokenizer-only release
    serves stale per-file/whole-map atom caches."""
    import reporails_cli.bundled as bundled_mod

    fake_models = tmp_path / "models"
    _seed_fake_model_dir(fake_models)
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)

    before = bio_tagger.multislot_fingerprint()
    (fake_models / "minilm-l6-v2" / "tokenizer.json").write_text('{"changed": true}')
    after = bio_tagger.multislot_fingerprint()
    assert before != after


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_fingerprint_ignores_the_contract_sidecar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The `two_encoder_contract.json` sidecar is no longer fetched, pinned,
    or read by the fingerprint — editing or removing it must not re-key."""
    import reporails_cli.bundled as bundled_mod

    fake_models = tmp_path / "models"
    _seed_fake_model_dir(fake_models)
    (fake_models / "two_encoder_contract.json").write_text("{}")
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)

    before = bio_tagger.multislot_fingerprint()
    (fake_models / "two_encoder_contract.json").write_text('{"changed": true}')
    after = bio_tagger.multislot_fingerprint()
    assert before == after

    (fake_models / "two_encoder_contract.json").unlink()
    still = bio_tagger.multislot_fingerprint()
    assert still == before


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_fingerprint_changes_when_embedder_graph_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Swapping the shared embedder graph must re-key the fingerprint, so a fresh
    embedder model never keeps a whole-map cache HIT."""
    import reporails_cli.bundled as bundled_mod

    fake_models = tmp_path / "models"
    _seed_fake_model_dir(fake_models)
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)

    before = bio_tagger.multislot_fingerprint()
    (fake_models / "minilm-l6-v2" / "onnx" / "model.onnx").write_bytes(b"embedder-v2-different-weights")
    after = bio_tagger.multislot_fingerprint()
    assert before != after


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_fingerprint_changes_when_head_a_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pre-existing coverage preserved: a head swap must still re-key."""
    import reporails_cli.bundled as bundled_mod

    fake_models = tmp_path / "models"
    _seed_fake_model_dir(fake_models)
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)

    before = bio_tagger.multislot_fingerprint()
    (fake_models / "multislot_head_encA.onnx").write_bytes(b"headA-v2-different-weights")
    after = bio_tagger.multislot_fingerprint()
    assert before != after


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_fingerprint_none_when_a_graph_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing graph must still short-circuit to the sentinel "none" fingerprint."""
    import reporails_cli.bundled as bundled_mod

    fake_models = tmp_path / "models"
    _seed_fake_model_dir(fake_models)
    (fake_models / "charge_encoder_encA.onnx").unlink()
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)

    assert bio_tagger.multislot_fingerprint() == "none"


# ── content-hash disk sidecar: memoize the hash across processes ──


def _clear_in_memory_hash_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate a fresh process: no in-memory cache, no already-loaded sidecar."""
    bio_graphs._graph_hash_cache.clear()
    monkeypatch.setattr(bio_graphs, "_sidecar_data", None)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_fingerprint_sidecar_avoids_rehash_in_a_fresh_process(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A 'fresh process' (in-memory caches cleared) reads the on-disk sidecar
    a PRIOR process wrote and does not re-hash an unchanged file."""
    import reporails_cli.bundled as bundled_mod
    from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir

    fake_models = tmp_path / "models"
    _seed_fake_model_dir(fake_models)
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)

    # First "process": computes and persists the sidecar.
    fp1 = bio_tagger.multislot_fingerprint()
    assert (get_global_cache_dir() / "fingerprint.json").is_file()
    assert not (fake_models / "fingerprint.json").exists()

    # Second "process": in-memory state gone, sidecar file remains.
    _clear_in_memory_hash_caches(monkeypatch)
    calls: list[Path] = []
    monkeypatch.setattr(bio_graphs, "_hash_file_bytes", lambda p: calls.append(p) or "should-not-be-used")

    fp2 = bio_tagger.multislot_fingerprint()
    assert fp2 == fp1
    assert calls == [], f"re-hashed unchanged files in a 'fresh process': {calls}"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_fingerprint_sidecar_rehashes_a_changed_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A file whose size/mtime moved since the sidecar was written is re-hashed, not trusted stale."""
    import reporails_cli.bundled as bundled_mod

    fake_models = tmp_path / "models"
    _seed_fake_model_dir(fake_models)
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)

    fp1 = bio_tagger.multislot_fingerprint()

    _clear_in_memory_hash_caches(monkeypatch)
    (fake_models / "charge_encoder_encA.onnx").write_bytes(b"encA-v2-different-weights")

    fp2 = bio_tagger.multislot_fingerprint()
    assert fp2 != fp1


@pytest.mark.unit
@pytest.mark.subsys_map
def test_concurrent_cold_graph_hash_does_not_raise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """REGRESSION: N threads racing a COLD `_graph_content_hash` (no sidecar entry yet,
    same shared `_sidecar_data` dict) must not raise out of `_save_sidecar`.

    Live-run defect: the MCP server dispatches one worker thread per file's pipeline
    run. On a cold cache, every thread's `multislot_fingerprint()` call funnels into
    `_graph_content_hash`, which read-modify-writes the process-global `_sidecar_data`
    dict and then `json.dumps`-serializes it — unlocked. One thread's `sidecar[key] = ...`
    mutation landing while another thread's `json.dumps` walks the same dict raises
    `RuntimeError: dictionary changed size during iteration`; `core/pipeline/mapping.py`
    lets that propagate out of `compute_identity` uncaught, and `interfaces/mcp/tools.py
    ::_build_map` swallows it into a bare `logger.warning` + `None` — surfaced to the
    MCP client only as `brief_unavailable`'s generic "produced no map".

    `json.dumps` is monkeypatched to walk `_sidecar_data`'s items with a small sleep
    between each — real concurrent runs hit this same window (a dict `json.dumps` is
    mid-iteration when another thread inserts a key), just too narrow to land reliably
    every run; widening it makes the interleaving deterministic instead of flaky.
    """
    import json
    import threading
    import time

    import reporails_cli.bundled as bundled_mod

    fake_models = tmp_path / "models"
    fake_models.mkdir()
    monkeypatch.setattr(bundled_mod, "get_models_path", lambda: fake_models)
    monkeypatch.setattr(bio_graphs, "_sidecar_paths", lambda: [fake_models / "fingerprint.json"])
    _clear_in_memory_hash_caches(monkeypatch)
    # Pre-load once so every thread shares the SAME empty dict object (the normal
    # steady state after a process's first sidecar touch) rather than racing the
    # one-time `_sidecar_data = {}` initialization too.
    bio_graphs._load_sidecar()

    real_dumps = json.dumps

    def slow_dumps(obj: object, *args: object, **kwargs: object) -> str:
        if obj is bio_graphs._sidecar_data:
            # Iterate the live dict view (NOT a copy) — a concurrent insert during
            # this walk must raise, exactly as it does inside the real `json.dumps`
            # C encoder's own live iteration over `dct.items()`.
            for _ in obj.items():  # type: ignore[union-attr]
                time.sleep(0.005)
        return real_dumps(obj, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(bio_graphs.json, "dumps", slow_dumps)

    n = 12
    paths = []
    for i in range(n):
        p = fake_models / f"cold-{i}.onnx"
        p.write_bytes(f"content-{i}".encode())
        paths.append(p)

    errors: list[BaseException] = []
    barrier = threading.Barrier(n)

    def worker(path: Path) -> None:
        barrier.wait()
        try:
            bio_graphs._graph_content_hash(path)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(p,)) for p in paths]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent cold graph-hash raised: {errors!r}"


# ── model-path guards (real bundled ONNX; skipped when absent) ───────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_word_features_pool_each_word_distinctly() -> None:
    """Each whitespace word pools its own token, not the global fallback mean
    (kills L212 `ws <= s` -> `ws < s`, which drops each word's first token and
    collapses every row to the shared all-token mean)."""
    if not bio_tagger.multislot_available():
        pytest.skip("encoder not bundled")
    feats, _word_spans, _covered = bio_tagger._word_features("alpha beta", bio_tagger._enc_a())
    assert feats.shape[0] == 2
    assert not np.allclose(feats[0], feats[1])


@pytest.mark.unit
@pytest.mark.subsys_map
def test_tag_atom_multislot_whitespace_is_empty_tuple() -> None:
    """Whitespace pools to no words → a neutral empty 5-tuple, never compound
    (kills L545 compound_candidate False->True; and L520 == -> != which then runs
    the head on empty feats and raises)."""
    if not bio_tagger.multislot_available():
        pytest.skip("dev multi-slot graphs not bundled")
    tup = bio_tagger.tag_atom_multislot("   ")
    assert tup.polarity == 0
    assert tup.compound_candidate is False
