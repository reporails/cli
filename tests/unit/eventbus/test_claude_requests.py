"""Sizing the API requests a transcript records: the rebuild of each request from shapes, blobs and rows."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

from reporails_cli.core.eventbus.adapters.claude_requests import content_size, feed_row, message_hash, shape_system_text
from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.eventbus.transcript import read_transcript
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.events import (
    EventRecord,
    ImageTokens,
    MessageSize,
    RequestChain,
    RequestSize,
    TranscriptCursor,
)
from reporails_cli.core.platform.utils.utils import compact_json

pytestmark = [pytest.mark.unit, pytest.mark.subsys_eventbus]

REAL = Path(os.environ.get("AILS_TEST_TRANSCRIPT", "/nonexistent/transcript.jsonl"))
STAMP = {"sessionId": "s1", "timestamp": "2026-11-03T10:00:00Z"}
USAGE = {"input_tokens": 1, "cache_creation_input_tokens": 2, "cache_read_input_tokens": 3}
SYSTEM_BLOB = {"role": "system", "content": [{"type": "text", "text": "note!"}]}
TOOL_RESULT_USER = {
    "role": "user",
    "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [{"type": "text", "text": "abcd"}]}],
}
ASSISTANT_BLOCKS = [
    {"type": "thinking", "thinking": "", "signature": "sig12"},
    {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/x"}, "caller": {"type": "direct"}},
]


def _blob(message: JsonObject) -> JsonObject:
    return {"type": "api-request-blob", "hash": message_hash(message["role"], message["content"]), "message": message}


_SYSTEM_DIGEST = hashlib.sha256(b"sys\n\ntem").hexdigest()


def _shape(shape_hash: str = "sh1") -> JsonObject:
    shape = {"system": [{"type": "text", "text": "sys"}, {"type": "text", "text": "tem"}], "tools": [{"name": "A"}]}
    return {"type": "api-request-shape", "shapeHash": shape_hash, "shape": shape}


def _user(content: object) -> JsonObject:
    return {"type": "user", "message": {"role": "user", "content": content}, **STAMP}


def _assistant(block: JsonObject, ref: str | None = None) -> JsonObject:
    row: JsonObject = {
        "type": "assistant",
        "message": {"id": "msg_1", "role": "assistant", "content": [block], "usage": USAGE},
        **STAMP,
    }
    if ref:
        row["requestRef"] = ref
    return row


def _request(request_id: str, keep: object, tail: object, shape_hash: object = "sh1") -> JsonObject:
    return {"type": "api-request", "id": request_id, "shapeHash": shape_hash, "keep": keep, "tail": tail, **STAMP}


def _merged(blocks: list[JsonObject], *, caller: bool) -> str:
    kept = blocks if caller else [{k: v for k, v in b.items() if k != "caller"} for b in blocks]
    return message_hash("assistant", kept)


def _fixture_rows() -> list[JsonObject]:
    string_user = "hello"
    string_hash = message_hash("user", string_user)
    tool_result_hash = message_hash("user", TOOL_RESULT_USER["content"])
    return [
        _shape(),
        _blob(SYSTEM_BLOB),
        _user(string_user),
        _assistant(ASSISTANT_BLOCKS[0], "req_1"),
        _assistant(ASSISTANT_BLOCKS[1], "req_1"),
        _request("req_1", 0, [message_hash("system", SYSTEM_BLOB["content"]), string_hash]),
        _user(TOOL_RESULT_USER["content"]),
        _request("req_2", 2, [_merged(ASSISTANT_BLOCKS, caller=False), tool_result_hash, "f" * 64]),
    ]


def _write(path: Path, rows: list[JsonObject]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _sizes(records: list[EventRecord]) -> list[RequestSize]:
    return [record.item for record in records if isinstance(record.item, RequestSize)]


def _read(path: Path) -> tuple[list[EventRecord], TranscriptCursor]:
    return read_transcript("claude", path, TranscriptCursor())


def test_fixture_rebuilds_each_request_by_part(tmp_path: Path) -> None:
    path = tmp_path / "s1.jsonl"
    _write(path, _fixture_rows())
    first, second = _sizes(_read(path)[0])
    assert first == RequestSize(
        "req_1", 6, 12, 1, MessageSize(user_text=5, notes=5), 0, ("A",), None, system_digest=_SYSTEM_DIGEST
    )
    # keep=2 holds the system note and "hello"; the tail adds the assistant response (the hash of the response
    # without `caller`), the tool result and one unknown hash that counts as unresolved.
    expected_calls = len("Read") + len('{"file_path":"/x"}')
    assert second == RequestSize(
        "req_2",
        6,
        12,
        1,
        MessageSize(user_text=5, notes=5, thinking=5, tool_calls=expected_calls, tool_results=4),
        1,
        ("A",),
        None,
        system_digest=_SYSTEM_DIGEST,
        reads=("/x",),
    )


def test_assistant_merge_is_registered_with_and_without_caller() -> None:
    chain = RequestChain()
    feed_row(chain, _assistant(ASSISTANT_BLOCKS[0]))
    feed_row(chain, _assistant(ASSISTANT_BLOCKS[1]))
    assert {_merged(ASSISTANT_BLOCKS, caller=True), _merged(ASSISTANT_BLOCKS, caller=False)} <= set(chain.pool)
    assert _merged(ASSISTANT_BLOCKS[:1], caller=True) in chain.pool


def test_running_hasher_matches_dumping_the_whole_message() -> None:
    blocks = [{"type": "text", "text": 'é"ü'}, {"type": "tool_use", "id": "i", "name": "n", "input": {"b": 1, "a": 2}}]
    prefix = hashlib.sha256(b'{"content":[')
    for index, block in enumerate(blocks):
        prefix.update(
            (b"," if index else b"")
            + json.dumps(block, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        )
    closed = prefix.copy()
    closed.update(b'],"role":"assistant"}')
    assert closed.hexdigest() == message_hash("assistant", blocks)


def test_incremental_read_matches_one_read(tmp_path: Path) -> None:
    rows = _fixture_rows()
    whole = tmp_path / "whole" / "s1.jsonl"
    whole.parent.mkdir()
    _write(whole, rows)
    split = tmp_path / "split" / "s1.jsonl"
    split.parent.mkdir()
    _write(split, rows[:4])
    first, cursor = read_transcript("claude", split, TranscriptCursor())
    with split.open("a", encoding="utf-8") as handle:
        handle.write("".join(json.dumps(row) + "\n" for row in rows[4:]))
    second, _ = read_transcript("claude", split, cursor)
    assert _sizes(first + second) == _sizes(_read(whole)[0])
    assert len(_sizes(first + second)) == 2


def test_unknown_shape_is_a_refusal_naming_the_field(tmp_path: Path) -> None:
    path = tmp_path / "s1.jsonl"
    _write(path, [_request("req_1", 0, [], "nope")])
    records, _ = _read(path)
    assert [r.refusal for r in records if r.event == "refusal"] == [
        "s1.jsonl: api-request shapeHash names no recorded shape"
    ]
    assert not _sizes(records)


def test_assistant_usage_carries_the_request_ref(tmp_path: Path) -> None:
    path = tmp_path / "s1.jsonl"
    _write(path, _fixture_rows())
    usage = [r.usage for r in _read(path)[0] if r.usage]
    assert [u.request_ref for u in usage] == ["req_1"]


def test_without_a_chain_the_request_rows_yield_nothing() -> None:
    from reporails_cli.core.eventbus.adapters.claude_transcript import ClaudeTranscriptAdapter

    adapter = ClaudeTranscriptAdapter()
    assert adapter.resolve_row(_shape(), None) == []
    assert adapter.resolve_row(_blob(SYSTEM_BLOB), None) == []
    assert adapter.resolve_row(_request("r", 0, []), None) == []


def test_non_string_request_ref_is_refused() -> None:
    from reporails_cli.core.eventbus.adapters.claude_transcript import ClaudeTranscriptAdapter

    row = _assistant({"type": "text", "text": "x"})
    row["requestRef"] = 7
    with pytest.raises(PayloadRefused, match="requestRef"):
        ClaudeTranscriptAdapter().resolve_row(row, None)


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        (_request("r", -1, []), "api-request keep"),
        (_request("r", True, []), "api-request keep"),
        (_request("r", "1", []), "api-request keep"),
        (_request("r", 0, "abc"), "api-request tail"),
        (_request("r", 0, ["a", 1]), "api-request tail"),
        (_request(1, 0, []), "api-request id"),  # type: ignore[arg-type]
        (_request("r", 0, [], 5), "api-request shapeHash"),
        ({"type": "api-request-blob", "hash": 3, "message": SYSTEM_BLOB}, "api-request-blob hash"),
        ({"type": "api-request-blob", "hash": "h", "message": "x"}, "api-request-blob message"),
        ({"type": "api-request-shape", "shapeHash": 1, "shape": {}}, "api-request-shape shapeHash"),
        ({"type": "api-request-shape", "shapeHash": "h", "shape": {"system": {}, "tools": []}}, "shape.system"),
        ({"type": "api-request-shape", "shapeHash": "h", "shape": {"system": [], "tools": "x"}}, "shape.tools"),
    ],
)
def test_malformed_request_rows_are_refused(row: JsonObject, reason: str) -> None:
    chain = RequestChain()
    feed_row(chain, _shape())
    with pytest.raises(PayloadRefused, match=reason):
        feed_row(chain, row)


def test_a_lone_surrogate_in_a_message_is_hashed_not_refused() -> None:
    chain = RequestChain()
    feed_row(chain, _user("abc\ud83d"))
    feed_row(chain, _assistant({"type": "text", "text": "x\ude00"}))
    assert message_hash("user", "abc\ud83d") in chain.pool
    assert len(chain.pool) >= 3


def _blob_of(content: object, role: str = "user") -> JsonObject:
    return {"type": "api-request-blob", "hash": "h", "message": {"role": role, "content": content}}


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        (_blob_of(42), "api-request-blob message content"),
        ({"type": "api-request-blob", "hash": "h", "message": {"role": "user"}}, "api-request-blob message content"),
        (_blob_of([{"type": "text", "text": 5}]), "api-request-blob text block text"),
        (_blob_of([{"type": "text"}], "assistant"), "api-request-blob text block text"),
        (_blob_of([{"type": "text", "text": None}], "system"), "api-request-blob text block text"),
        (_blob_of([{"type": "tool_use", "input": {}}], "assistant"), "api-request-blob tool_use block name"),
        (_blob_of([{"type": "tool_result", "tool_use_id": "t"}]), "tool_result content"),
        (_blob_of([{"type": "tool_result", "content": "x"}]), "tool_result block has no string tool_use_id"),
        (_blob_of([{"type": "thinking"}], "assistant"), "api-request-blob thinking block signature"),
        (_blob_of([{"type": "mystery"}]), "api-request-blob content has a block of unknown type 'mystery'"),
        (_blob_of(["text"]), "api-request-blob content has a block that is not an object"),
        (_blob_of([{"type": "tool_addition", "tool": "x"}], "system"), "api-request-blob tool_addition block tool"),
        (_assistant({"type": "tool_use", "id": "t", "input": {}}), "assistant row tool_use block name"),
        (_assistant({"type": "text", "text": 3}), "assistant row text block text"),
        (_user([{"type": "text", "text": 3}]), "user row text block text"),
        (_user(12), "user row message content"),
        (
            {"type": "api-request-shape", "shapeHash": "h", "shape": {"system": [{"type": "text"}], "tools": []}},
            "api-request-shape shape.system block text",
        ),
    ],
)
def test_request_content_that_is_not_the_pinned_shape_is_refused(row: JsonObject, reason: str) -> None:
    with pytest.raises(PayloadRefused, match=reason):
        feed_row(RequestChain(), row)


def _png(width: int, height: int) -> str:
    header = (
        b"\x89PNG\r\n\x1a\n" + (13).to_bytes(4, "big") + b"IHDR" + width.to_bytes(4, "big") + height.to_bytes(4, "big")
    )
    return base64.b64encode(header + bytes(9)).decode()


def _image(data: str, media_type: str = "image/png", kind: str = "base64") -> JsonObject:
    return {"type": "image", "source": {"type": kind, "media_type": media_type, "data": data}}


def test_every_block_type_that_occurs_is_sized() -> None:
    chain = RequestChain()
    feed_row(chain, {**_blob_of([_image(_png(200, 200)), {"type": "document"}]), "hash": "im"})
    feed_row(chain, {**_blob_of([{"type": "redacted_thinking", "data": "abc"}], "assistant"), "hash": "rt"})
    addition = {"type": "tool_addition", "tool": {"type": "tool_definition", "definition": {"name": "é"}}}
    feed_row(chain, {**_blob_of([addition], "system"), "hash": "ta"})
    nested = [
        {
            "type": "tool_result",
            "tool_use_id": "t",
            "content": [_image(_png(1920, 1080)), {"type": "text", "text": "ab"}],
        }
    ]
    feed_row(chain, {**_blob_of(nested), "hash": "tr"})
    assert chain.pool["im"] == MessageSize(images=ImageTokens(64, 64), unpriced_images=1)
    assert chain.pool["rt"] == MessageSize(thinking=3)
    assert chain.pool["ta"] == MessageSize(notes=len('{"type":"tool_definition","definition":{"name":"é"}}'))
    # An image inside a tool result is a result image, not one of the message's own.
    assert chain.pool["tr"] == MessageSize(tool_results=2, result_images=ImageTokens(1560, 2691))


@pytest.mark.parametrize(
    "block",
    [
        _image("http://x/y.png", kind="url"),
        _image("!!!not base64!!!"),
        _image(_png(10, 10), media_type="image/bmp"),
        _image(_png(0, 10)),
    ],
    ids=["url source", "bad base64", "unknown media type", "zero width"],
)
def test_an_image_that_cannot_be_priced_is_counted_unpriced(block: JsonObject) -> None:
    assert content_size("user", [block], "x") == MessageSize(unpriced_images=1)


def test_an_image_whose_source_is_not_an_object_is_refused() -> None:
    with pytest.raises(PayloadRefused, match="image block source is not an object"):
        content_size("user", [{"type": "image", "source": "x"}], "x")


@pytest.mark.parametrize(
    ("params", "tier"),
    [
        ({"model": "claude-opus-5-5"}, True),
        ({"model": "claude-sonnet-4-6"}, False),
        ({"model": "gpt"}, None),
        (None, None),
    ],
)
def test_a_request_carries_the_tier_of_its_models_image_price(params: object, tier: bool | None) -> None:
    chain = RequestChain()
    feed_row(chain, _shape())
    size = feed_row(chain, {**_request("r", 0, []), "params": params})
    assert size is not None and size.high_resolution is tier


def test_tool_definitions_and_inputs_are_sized_as_compact_json() -> None:
    chain = RequestChain()
    tools = [{"name": "A", "input_schema": {"type": "object", "properties": {}}}]
    feed_row(chain, {"type": "api-request-shape", "shapeHash": "s", "shape": {"system": [], "tools": tools}})
    assert chain.shapes["s"][1] == len(compact_json(tools[0], ensure_ascii=False))
    feed_row(chain, _assistant({"type": "tool_use", "id": "t", "name": "Tool", "input": {"a": [1, 2], "b": "é"}}))
    (size,) = chain.pool.values()
    assert size.tool_calls == len("Tool") + len('{"a":[1,2],"b":"é"}')


@pytest.mark.skipif(not REAL.is_file(), reason="set AILS_TEST_TRANSCRIPT to a session transcript")
def test_real_transcript_rebuilds_with_few_unresolved() -> None:
    records, _ = _read(REAL)
    sizes = _sizes(records)
    assert sizes, "no api-request rows read"
    main = [r.item for r in records if isinstance(r.item, RequestSize) and r.subagent_id is None]
    assert sum(size.unresolved for size in main) <= 20
    # The subagent files rebuild too, with a few more tails whose messages the file never recorded.
    assert sum(size.unresolved for size in sizes) <= len(sizes) // 10
    ids = {size.request_id for size in sizes}
    refs = {r.usage.request_ref for r in records if r.usage and r.usage.request_ref and r.subagent_id is None}
    assert refs
    assert refs <= ids


def test_a_request_carries_the_names_of_the_tools_of_its_shape() -> None:
    chain = RequestChain()
    tools = [{"name": "Read"}, {"name": "Grep", "input_schema": {}}]
    feed_row(chain, {"type": "api-request-shape", "shapeHash": "s", "shape": {"system": [], "tools": tools}})
    size = feed_row(chain, {"type": "api-request", "id": "r", "shapeHash": "s", "keep": 0, "tail": []})
    assert size is not None and size.tool_names == ("Read", "Grep")


def test_a_tool_with_no_string_name_refuses_its_shape() -> None:
    row = {"type": "api-request-shape", "shapeHash": "s", "shape": {"system": [], "tools": [{"name": 3}]}}
    with pytest.raises(PayloadRefused, match=r"shape\.tools"):
        feed_row(RequestChain(), row)


def test_a_shape_that_is_not_an_object_refuses_its_system_text() -> None:
    row = {"type": "api-request-shape", "shapeHash": "s", "shape": []}
    with pytest.raises(PayloadRefused, match="shape is not an object"):
        shape_system_text(row, "s")
