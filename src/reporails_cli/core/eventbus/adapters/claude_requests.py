"""Sizing the API requests a Claude Code transcript records, from its request rows.

A transcript file holds `api-request-shape` rows (`shapeHash`, a string, and `shape.system`, a list of
`{type, text}` blocks, and `shape.tools`, a list of tool definitions), `api-request-blob` rows (`hash`, a string,
and `message`, `{role, content}` with role `system`, `user` or `assistant`), `api-request` rows (`id`, equal to the
`requestRef` of the assistant rows that answer it, `shapeHash`, `keep`, a non-negative whole number of the previous
request's messages this one keeps, and `tail`, a list of the hashes of the messages it appends) and the `user` and
`assistant` rows whose messages those hashes name; Claude Code records them from 2.1.309. The fields
`querySource`, `params`, `cacheControl` and `requestDigest` are not read. A hash that names no known message
counts as unresolved and keeps its place in the request as an empty size. `feed_row` takes every row of one file
in order and keeps only the sizes of what it sees; the text of a message is never stored.

A message's hash is the sha256 of its `{role, content}` object written with sorted keys, compact separators and
no ASCII escaping. A `user` row's message is known under that hash, and under the hash of its string content
written as one text block. The rows of one assistant response share `message.id`, one row per content block; the
response as it stands after each row is known under its hash, and under the hash of the same response with the
`caller` key taken off every block.
"""

from __future__ import annotations

import hashlib
import json

from reporails_cli.core.eventbus.adapters.claude_calls import blocks_text
from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.platform.contract.json_value import (
    JsonObject,
    JsonValue,
    as_list,
    as_object,
    as_str,
    opt_int,
    opt_str,
    strict_str_list,
)
from reporails_cli.core.platform.dto.events import MessageSize, RequestChain, RequestSize
from reporails_cli.core.platform.utils.utils import compact_json

_MERGE_OPEN = b'{"content":['
_MERGE_CLOSE = b'],"role":"assistant"}'
_CALLER = "caller"


def _canonical(value: JsonValue) -> str:
    return compact_json(value, ensure_ascii=False, sort_keys=True)


def message_hash(role: JsonValue, content: JsonValue) -> str:
    """The hash a message is known under: the sha256 of its role and content object."""
    return hashlib.sha256(_canonical({"role": role, "content": content}).encode()).hexdigest()


def _text_part(role: str, chars: int) -> MessageSize:
    if role == "assistant":
        return MessageSize(assistant_text=chars)
    if role == "system":
        return MessageSize(notes=chars)
    return MessageSize(user_text=chars)


def _block_size(role: str, block: JsonObject) -> MessageSize:
    kind = block.get("type")
    if kind == "text":
        return _text_part(role, len(as_str(block.get("text"))))
    if kind == "tool_use":
        call = len(as_str(block.get("name"))) + len(json.dumps(block.get("input"), ensure_ascii=False))
        return MessageSize(tool_calls=call)
    if kind == "tool_result":
        texts = blocks_text(block.get("content"), "tool_result") or []
        return MessageSize(tool_results=sum(len(text) for text in texts))
    if kind == "thinking":
        return MessageSize(thinking=len(as_str(block.get("signature"))))
    if kind == "redacted_thinking":
        return MessageSize(thinking=len(as_str(block.get("data"))))
    return MessageSize()


def content_size(role: str, content: JsonValue) -> MessageSize:
    """The size of a message's content by part: a string counts as text of the role, a list by block."""
    if isinstance(content, str):
        return _text_part(role, len(content))
    total = MessageSize()
    for block in as_list(content):
        total = total + _block_size(role, as_object(block))
    return total


def _register_user(chain: RequestChain, row: JsonObject) -> None:
    message = as_object(row.get("message"))
    role, content = message.get("role"), message.get("content")
    if not isinstance(role, str) or content is None:
        return
    size = content_size(role, content)
    chain.pool[message_hash(role, content)] = size
    if isinstance(content, str):
        chain.pool[message_hash(role, [{"type": "text", "text": content}])] = size


def _drop_merge(chain: RequestChain) -> None:
    chain.merge_id = None
    chain.merge_with_caller = None
    chain.merge_without_caller = None
    chain.merge_size = MessageSize()
    chain.merge_blocks = 0


def _register_assistant(chain: RequestChain, row: JsonObject) -> None:
    message = as_object(row.get("message"))
    message_id, content = opt_str(message.get("id")), message.get("content")
    if message_id is None or message.get("role") != "assistant" or not isinstance(content, list):
        _drop_merge(chain)
        return
    if chain.merge_id != message_id or chain.merge_with_caller is None or chain.merge_without_caller is None:
        _drop_merge(chain)
        chain.merge_id = message_id
        chain.merge_with_caller = hashlib.sha256(_MERGE_OPEN)
        chain.merge_without_caller = hashlib.sha256(_MERGE_OPEN)
    with_caller, without_caller = chain.merge_with_caller, chain.merge_without_caller
    for block in content:
        separator = b"," if chain.merge_blocks else b""
        with_caller.update(separator + _canonical(block).encode())
        bare = {key: value for key, value in block.items() if key != _CALLER} if isinstance(block, dict) else block
        without_caller.update(separator + _canonical(bare).encode())
        chain.merge_blocks += 1
        chain.merge_size = chain.merge_size + _block_size("assistant", as_object(block))
    for running in (with_caller, without_caller):
        closed = running.copy()
        closed.update(_MERGE_CLOSE)
        chain.pool[closed.hexdigest()] = chain.merge_size


def _register_blob(chain: RequestChain, row: JsonObject) -> None:
    what = "api-request-blob"
    digest = row.get("hash")
    if not isinstance(digest, str):
        raise PayloadRefused(f"{what} hash is not a string")
    message = row.get("message")
    if not isinstance(message, dict):
        raise PayloadRefused(f"{what} message is not an object")
    role = message.get("role")
    if not isinstance(role, str):
        raise PayloadRefused(f"{what} message role is not a string")
    chain.pool[digest] = content_size(role, message.get("content"))


def _register_shape(chain: RequestChain, row: JsonObject) -> None:
    what = "api-request-shape"
    shape_hash = row.get("shapeHash")
    if not isinstance(shape_hash, str):
        raise PayloadRefused(f"{what} shapeHash is not a string")
    shape = row.get("shape")
    if not isinstance(shape, dict):
        raise PayloadRefused(f"{what} shape is not an object")
    system, tools = shape.get("system"), shape.get("tools")
    if not isinstance(system, list):
        raise PayloadRefused(f"{what} shape.system is not a list")
    if not isinstance(tools, list):
        raise PayloadRefused(f"{what} shape.tools is not a list")
    system_chars = sum(len(as_str(as_object(block).get("text"))) for block in system)
    tools_chars = sum(len(json.dumps(tool, ensure_ascii=False)) for tool in tools)
    chain.shapes[shape_hash] = (system_chars, tools_chars, len(tools))


def _request(chain: RequestChain, row: JsonObject) -> RequestSize:
    what = "api-request"
    request_id, shape_hash = row.get("id"), row.get("shapeHash")
    if not isinstance(request_id, str):
        raise PayloadRefused(f"{what} id is not a string")
    if not isinstance(shape_hash, str):
        raise PayloadRefused(f"{what} shapeHash is not a string")
    keep = opt_int(row.get("keep"))
    if keep is None or keep < 0:
        raise PayloadRefused(f"{what} keep is not a non-negative whole number")
    tail = strict_str_list(row.get("tail"))
    if tail is None:
        raise PayloadRefused(f"{what} tail is not a list of strings")
    shape = chain.shapes.get(shape_hash)
    if shape is None:
        raise PayloadRefused(f"{what} shapeHash names no recorded shape")
    unresolved = sum(1 for digest in tail if digest not in chain.pool)
    # An unknown message keeps its place as an empty size, so the next request's `keep` still counts it.
    kept = min(keep, len(chain.prefix) - 1)
    del chain.prefix[kept + 1 :]
    total = chain.prefix[kept]
    for digest in tail:
        total += chain.pool.get(digest, MessageSize())
        chain.prefix.append(total)
    return RequestSize(
        request_id,
        *shape,
        total.user_text,
        total.notes,
        total.assistant_text,
        total.thinking,
        total.tool_calls,
        total.tool_results,
        kept + len(tail),
        unresolved,
    )


def feed_row(chain: RequestChain, row: JsonObject) -> RequestSize | None:
    """Take one row of a transcript file into `chain`; the size of the request an `api-request` row describes,
    None for every other row. Refuses an `api-request-shape`, `api-request-blob` or `api-request` row whose
    fields are not the pinned shape, naming the row type and the field."""
    kind = row.get("type")
    if kind == "api-request-blob":
        _register_blob(chain, row)
    elif kind == "api-request-shape":
        _register_shape(chain, row)
    elif kind == "user":
        _drop_merge(chain)
        _register_user(chain, row)
    elif kind == "assistant":
        _register_assistant(chain, row)
    elif kind == "api-request":
        return _request(chain, row)
    return None
