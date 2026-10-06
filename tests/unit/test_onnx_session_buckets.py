"""Model-free tests for bucket planning, feed building and bucket forward trimming."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import numpy as np
import pytest

from reporails_cli.core.mapper import onnx_session
from reporails_cli.core.mapper.bio_tagger import _BioEncoder
from reporails_cli.core.mapper.onnx_session import _OnnxEncoderSession, _Tokens


class _FakeTokenizer:
    """Whitespace tokenizer: one token per word, id = word length, offsets = word spans."""

    def __init__(self, pad_to: int | None = None) -> None:
        self.batch_sizes: list[int] = []
        self.pad_to = pad_to

    def _one(self, text: str) -> Any:
        ids, offsets, pos = [], [], 0
        for w in text.split():
            start = text.index(w, pos)
            pos = start + len(w)
            ids.append(len(w))
            offsets.append((start, pos))
        mask = [1] * len(ids)
        if self.pad_to is not None:
            while len(ids) < self.pad_to:
                ids.append(0)
                offsets.append((0, 0))
                mask.append(0)
        return SimpleNamespace(ids=ids, offsets=offsets, attention_mask=mask)

    def encode_batch(self, texts: list[str]) -> list[Any]:
        self.batch_sizes.append(len(texts))
        return [self._one(t) for t in texts]

    def encode(self, text: str) -> Any:
        return self._one(text)


def _session(tokenizer: _FakeTokenizer | None = None, needs_type_ids: bool = False) -> _OnnxEncoderSession:
    enc = object.__new__(_OnnxEncoderSession)
    enc._tokenizer = tokenizer or _FakeTokenizer()
    enc._needs_token_type_ids = needs_type_ids
    return enc


def _flat_texts(buckets: list[list[str]]) -> list[str]:
    return [t for b in buckets for t in b]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_plan_buckets_empty_input() -> None:
    assert _session().plan_buckets([], 4) == ([], [])


@pytest.mark.unit
@pytest.mark.subsys_map
def test_plan_buckets_dedups_and_maps_slots_for_duplicates() -> None:
    texts = ["a b", "a b c d", "a b", "x", "a b c d", "x"]
    buckets, slot = _session().plan_buckets(texts, 10)
    flat = _flat_texts(buckets)
    assert sorted(flat) == sorted({"a b", "a b c d", "x"})
    assert len(slot) == len(texts)
    assert [flat[s] for s in slot] == texts
    assert slot[0] == slot[2] and slot[1] == slot[4] and slot[3] == slot[5]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_plan_buckets_orders_longest_first_by_token_count() -> None:
    texts = ["a", "a b c", "a b", "a b c d e", "a b c d"]
    buckets, _ = _session().plan_buckets(texts, 10)
    counts = [len(t.split()) for t in _flat_texts(buckets)]
    assert counts == [5, 4, 3, 2, 1]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_plan_buckets_splits_into_bucket_size_groups() -> None:
    texts = [" ".join(["w"] * n) for n in range(1, 8)]
    buckets, slot = _session().plan_buckets(texts, 3)
    assert [len(b) for b in buckets] == [3, 3, 1]
    flat = _flat_texts(buckets)
    assert [flat[s] for s in slot] == texts


@pytest.mark.unit
@pytest.mark.subsys_map
def test_plan_buckets_counts_tokens_in_bounded_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(onnx_session, "_COUNT_CHUNK", 4)
    tok = _FakeTokenizer()
    texts = [" ".join(["w"] * (i % 5 + 1)) + f" u{i}" for i in range(10)]
    buckets, slot = _session(tok).plan_buckets(texts, 3)
    assert tok.batch_sizes == [4, 4, 2]
    flat = _flat_texts(buckets)
    assert [flat[s] for s in slot] == texts
    counts = [len(t.split()) for t in flat]
    assert counts == sorted(counts, reverse=True)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_plan_buckets_counts_ignore_padding_in_encodings() -> None:
    texts = ["a", "a b c", "a b"]
    buckets, _ = _session(_FakeTokenizer(pad_to=9)).plan_buckets(texts, 10)
    assert _flat_texts(buckets) == ["a b c", "a b", "a"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_encode_feed_zero_pads_and_masks_to_bucket_width() -> None:
    bucket = [_Tokens("abc de", [3, 2], [(0, 3), (4, 6)]), _Tokens("f", [1], [(0, 1)])]
    feed = _session()._encode_feed(bucket)
    assert feed["input_ids"].dtype == np.int64
    assert feed["input_ids"].tolist() == [[3, 2], [1, 0]]
    assert feed["attention_mask"].tolist() == [[1, 1], [1, 0]]
    assert "token_type_ids" not in feed


@pytest.mark.unit
@pytest.mark.subsys_map
def test_encode_feed_adds_zero_token_type_ids_when_graph_needs_them() -> None:
    bucket = [_Tokens("ab c", [2, 1], [(0, 2), (3, 4)]), _Tokens("d", [1], [(0, 1)])]
    feed = _session(needs_type_ids=True)._encode_feed(bucket)
    assert feed["token_type_ids"].shape == feed["input_ids"].shape
    assert not feed["token_type_ids"].any()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_forward_bucket_trims_padding_from_hidden_states() -> None:
    seen: dict[str, Any] = {}

    class _Session:
        def run(self, names: list[str], feed: dict[str, Any]) -> list[Any]:
            seen.update(feed)
            b, t = feed["input_ids"].shape
            hidden = np.arange(b * t * 2, dtype=np.float32).reshape(b, t, 2)
            return [hidden]

    enc = object.__new__(_BioEncoder)
    enc._tokenizer = _FakeTokenizer()
    enc._needs_token_type_ids = False
    enc._session = _Session()

    out = enc.forward_bucket(["aa bb cc", "d"])
    assert seen["input_ids"].shape == (2, 3)
    (h0, o0), (h1, o1) = out
    assert h0.shape == (3, 2) and h1.shape == (1, 2)
    assert o0 == [(0, 2), (3, 5), (6, 8)] and o1 == [(0, 1)]
    assert h1.tolist() == [[6.0, 7.0]]
