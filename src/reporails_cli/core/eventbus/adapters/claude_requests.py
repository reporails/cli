"""Sizing the API requests a Claude Code transcript records, from its request rows.

A transcript file holds `api-request-shape` rows (`shapeHash`, a string, and `shape.system`, a list of
`{type, text}` blocks, and `shape.tools`, a list of tool definitions), `api-request-blob` rows (`hash`, a string,
and `message`, `{role, content}` with role `system`, `user` or `assistant`), `api-request` rows (`id`, equal to the
`requestRef` of the assistant rows that answer it, `shapeHash`, `keep`, a non-negative whole number of the previous
request's messages this one keeps, and `tail`, a list of the hashes of the messages it appends) and the `user` and
`assistant` rows whose messages those hashes name; Claude Code records them from 2.1.309. The fields
`querySource`, `cacheControl` and `requestDigest` are not read, and of `params` only `model`, `max_tokens`,
`thinking.type` and `output_config.effort` are. A hash that names no known message counts as unresolved and keeps its
place in the request as an empty size. `feed_row` takes every row of one file in order and keeps only the sizes of
what it sees and the names of the tools a request was sent with; the text of a message is never stored. An image costs
the tokens its header's size works out to (`claude_images`),
counted apart from the characters of the text.

A message's hash is the sha256 of its `{role, content}` object written with sorted keys, compact separators and
no ASCII escaping. A `user` row's message is known under that hash, and under the hash of its string content
written as one text block. The rows of one assistant response share `message.id`, one row per content block; the
response as it stands after each row is known under its hash, and under the hash of the same response with the
`caller` key taken off every block.

A text counts as notes when its role is `system`, or when its role is `user` and it opens, after any leading
whitespace, with `<system-reminder>`; as assistant text for `assistant`; as user text otherwise.
"""

from __future__ import annotations

import hashlib

from reporails_cli.core.eventbus.adapters.claude_calls import tool_result
from reporails_cli.core.eventbus.adapters.claude_images import high_resolution, price_image
from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.platform.contract.json_value import (
    JsonObject,
    JsonValue,
    as_object,
    opt_int,
    opt_str,
    strict_str_list,
)
from reporails_cli.core.platform.dto.events import AssistantMerge, MessageText, RequestChain, RequestConfig, RequestSize
from reporails_cli.core.platform.dto.message_size import ImageTokens, MessageSize
from reporails_cli.core.platform.utils.utils import compact_json

# What joins the text blocks of one message or system prompt.
BLOCK_SEPARATOR = "\n\n"
_MERGE_OPEN = b'{"content":['
_MERGE_CLOSE = b'],"role":"assistant"}'
_CALLER = "caller"
# Block types that carry no characters of their own: priced in tokens, or counted as unpriced.
_PICTURE_BLOCKS = ("image", "document")
# The tag Claude Code opens its own injected text with.
_REMINDER_TAG = "<system-reminder>"
# The field that holds the characters of each kind of thinking block.
_THINKING_FIELDS = {"thinking": "signature", "redacted_thinking": "data"}


def _canonical(value: JsonValue) -> str:
    return compact_json(value, ensure_ascii=False, sort_keys=True)


def _encode(text: str) -> bytes:
    """`text` as bytes for hashing; a lone surrogate in a message keeps its own bytes."""
    return text.encode("utf-8", errors="surrogatepass")


def message_hash(role: JsonValue, content: JsonValue) -> str:
    """The hash a message is known under: the sha256 of its role and content object."""
    return hashlib.sha256(_encode(_canonical({"role": role, "content": content}))).hexdigest()


def _text_part(role: str, text: str) -> MessageSize:
    """The size of a text by part: assistant text for the assistant, notes for a `system` text or a `user` text
    that opens with a `<system-reminder>` tag, user text otherwise."""
    chars = len(text)
    if role == "assistant":
        return MessageSize(assistant_text=chars)
    if role == "system" or (role == "user" and text.lstrip().startswith(_REMINDER_TAG)):
        return MessageSize(notes=chars)
    return MessageSize(user_text=chars)


def _string_field(block: JsonObject, field: str, what: str) -> str:
    value = block.get(field)
    if not isinstance(value, str):
        raise PayloadRefused(f"{what} {block.get('type')} block {field} is not a string")
    return value


def _tool_use_size(block: JsonObject, what: str) -> MessageSize:
    name = _string_field(block, "name", what)
    return MessageSize(tool_calls=len(name) + len(compact_json(block.get("input"), ensure_ascii=False)))


def _tool_addition_size(block: JsonObject, what: str) -> MessageSize:
    tool = block.get("tool")
    if not isinstance(tool, dict):
        raise PayloadRefused(f"{what} tool_addition block tool is not an object")
    return MessageSize(notes=len(compact_json(tool, ensure_ascii=False)))


def _picture(block: JsonObject, what: str) -> tuple[ImageTokens, int]:
    """The tokens an `image` or `document` block costs and how many blocks could not be priced (0 or 1). A
    document is never priced; an image whose `source` is not an object is refused."""
    if block.get("type") == "document":
        return ImageTokens(), 1
    source = block.get("source")
    if not isinstance(source, dict):
        raise PayloadRefused(f"{what} image block source is not an object")
    priced = price_image(source)
    return (ImageTokens(), 1) if priced is None else (priced, 0)


def _result_pictures(block: JsonObject, what: str) -> MessageSize:
    """The images inside the content of a `tool_result` block, as result images."""
    content = block.get("content")
    found = MessageSize()
    if not isinstance(content, list):
        return found
    for item in content:
        if isinstance(item, dict) and item.get("type") in _PICTURE_BLOCKS:
            tokens, unpriced = _picture(item, what)
            found = found + MessageSize(result_images=tokens, unpriced_images=unpriced)
    return found


def _block_size(role: str, block: JsonValue, what: str) -> MessageSize:
    if not isinstance(block, dict):
        raise PayloadRefused(f"{what} content has a block that is not an object")
    kind = block.get("type")
    if kind == "text":
        return _text_part(role, _string_field(block, "text", what))
    if kind == "tool_use":
        return _tool_use_size(block, what)
    if kind == "tool_result":
        return MessageSize(tool_results=tool_result(block).chars or 0) + _result_pictures(block, what)
    field = _THINKING_FIELDS.get(kind) if isinstance(kind, str) else None
    if field is not None:
        return MessageSize(thinking=len(_string_field(block, field, what)))
    if kind == "tool_addition":
        return _tool_addition_size(block, what)
    if kind in _PICTURE_BLOCKS:
        tokens, unpriced = _picture(block, what)
        return MessageSize(images=tokens, unpriced_images=unpriced)
    raise PayloadRefused(f"{what} content has a block of unknown type {kind!r}")


def _block_texts(role: str, content: JsonValue) -> tuple[MessageText, ...]:
    """The notes and thinking a message's content holds, in order: a text that counts as notes, a tool addition, and
    each thinking block with its text (empty for a signed block that carries none). A block of any other kind
    holds none; `content_size` has already refused content that is not readable."""
    blocks: list[JsonValue] = (
        [{"type": "text", "text": content}]
        if isinstance(content, str)
        else content
        if isinstance(content, list)
        else []
    )
    found: list[MessageText] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        kind, text = block.get("type"), block.get("text")
        if kind == "text" and isinstance(text, str) and _text_part(role, text).notes:
            found.append(("notes", text))
        elif kind == "tool_addition":
            found.append(("notes", compact_json(block.get("tool"), ensure_ascii=False)))
        elif kind == "thinking":
            thought = block.get("thinking")
            found.append(("thinking", thought if isinstance(thought, str) else ""))
    return tuple(found)


def _remember(chain: RequestChain, digests: list[str], role: str, content: JsonValue) -> None:
    """Keep the notes and thinking of a message under each of its `digests`, when the chain keeps text."""
    if chain.texts is None:
        return
    found = _block_texts(role, content)
    for digest in digests:
        chain.texts[digest] = found


def content_size(role: str, content: JsonValue, what: str) -> MessageSize:
    """The size of a message's content by part: a string counts as text of the role (a `user` text opening with
    `<system-reminder>` counts as notes), a list by block. Refuses
    content that is neither, naming the row type `what`."""
    if isinstance(content, str):
        return _text_part(role, content)
    if not isinstance(content, list):
        raise PayloadRefused(f"{what} message content is neither a string nor a list")
    total = MessageSize()
    for block in content:
        total = total + _block_size(role, block, what)
    return total


def _register_user(chain: RequestChain, row: JsonObject) -> None:
    message = as_object(row.get("message"))
    role, content = message.get("role"), message.get("content")
    if not isinstance(role, str) or content is None:
        return
    size = content_size(role, content, "user row")
    digests = [message_hash(role, content)]
    if isinstance(content, str):
        digests.append(message_hash(role, [{"type": "text", "text": content}]))
    for digest in digests:
        chain.pool[digest] = size
    _remember(chain, digests, role, content)


def _drop_merge(chain: RequestChain) -> None:
    chain.merge = AssistantMerge()


def _register_assistant(chain: RequestChain, row: JsonObject) -> None:
    message = as_object(row.get("message"))
    message_id, content = opt_str(message.get("id")), message.get("content")
    if message_id is None or message.get("role") != "assistant" or not isinstance(content, list):
        _drop_merge(chain)
        return
    merge = chain.merge
    with_caller, without_caller = merge.with_caller, merge.without_caller
    if merge.message_id != message_id or with_caller is None or without_caller is None:
        with_caller, without_caller = hashlib.sha256(_MERGE_OPEN), hashlib.sha256(_MERGE_OPEN)
        merge = chain.merge = AssistantMerge(message_id, with_caller, without_caller)
    for block in content:
        separator = b"," if merge.blocks else b""
        with_caller.update(separator + _encode(_canonical(block)))
        bare = {key: value for key, value in block.items() if key != _CALLER} if isinstance(block, dict) else block
        without_caller.update(separator + _encode(_canonical(bare)))
        merge.blocks += 1
        merge.size = merge.size + _block_size("assistant", block, "assistant row")
        if chain.texts is not None:
            merge.texts.extend(_block_texts("assistant", [block]))
    for running in (with_caller, without_caller):
        closed = running.copy()
        closed.update(_MERGE_CLOSE)
        chain.pool[closed.hexdigest()] = merge.size
        if chain.texts is not None:
            chain.texts[closed.hexdigest()] = tuple(merge.texts)


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
    chain.pool[digest] = content_size(role, message.get("content"), what)
    _remember(chain, [digest], role, message.get("content"))


def _system_text(block: JsonValue, what: str) -> str:
    if not isinstance(block, dict):
        raise PayloadRefused(f"{what} shape.system has a block that is not an object")
    text = block.get("text")
    if not isinstance(text, str):
        raise PayloadRefused(f"{what} shape.system block text is not a string")
    return text


def _tool_name(tool: JsonValue, what: str) -> str:
    name = tool.get("name") if isinstance(tool, dict) else None
    if not isinstance(name, str):
        raise PayloadRefused(f"{what} shape.tools has a tool with no string name")
    return name


def _shape_hash(row: JsonObject, what: str) -> str:
    shape_hash = row.get("shapeHash")
    if not isinstance(shape_hash, str):
        raise PayloadRefused(f"{what} shapeHash is not a string")
    return shape_hash


def _shape_parts(row: JsonObject, what: str) -> tuple[list[JsonValue], list[JsonValue]]:
    """The system blocks and the tool definitions of a shape row, refusing a shape that holds neither as a list."""
    shape = row.get("shape")
    if not isinstance(shape, dict):
        raise PayloadRefused(f"{what} shape is not an object")
    system, tools = shape.get("system"), shape.get("tools")
    if not isinstance(system, list):
        raise PayloadRefused(f"{what} shape.system is not a list")
    if not isinstance(tools, list):
        raise PayloadRefused(f"{what} shape.tools is not a list")
    return system, tools


def _system_texts(row: JsonObject, what: str) -> list[str]:
    return [_system_text(block, what) for block in _shape_parts(row, what)[0]]


def _register_shape(chain: RequestChain, row: JsonObject) -> None:
    what = "api-request-shape"
    shape_hash = _shape_hash(row, what)
    tools = _shape_parts(row, what)[1]
    system_chars = sum(len(text) for text in _system_texts(row, what))
    tools_chars = sum(len(compact_json(tool, ensure_ascii=False)) for tool in tools)
    chain.shapes[shape_hash] = (system_chars, tools_chars, len(tools))
    system = BLOCK_SEPARATOR.join(_system_texts(row, what))
    chain.system_digests[shape_hash] = hashlib.sha256(_encode(system)).hexdigest()
    chain.tool_names[shape_hash] = tuple(_tool_name(tool, what) for tool in tools)


def note_body(text: str) -> str:
    """A note's text without the `<system-reminder>` tag that opens it and the one that closes it."""
    return text.replace(_REMINDER_TAG, "").replace(_REMINDER_TAG.replace("<", "</"), "").strip()


def request_blocks(chain: RequestChain) -> list[MessageText]:
    """The notes and thinking of the messages of the request the chain last took, in order; a message the chain
    knows nothing of holds none. Empty for a chain that keeps no text."""
    texts = chain.texts or {}
    return [block for digest in chain.trail for block in texts.get(digest, ())]


def request_shape_ref(row: JsonObject) -> tuple[str, str] | None:
    """The id and the `shapeHash` an `api-request` row names; None for any other row, a refusal for one whose hash is
    not a string."""
    if row.get("type") != "api-request":
        return None
    return opt_str(row.get("id")) or "", _shape_hash(row, "api-request")


def shape_text(row: JsonObject, shape_hash: str, item: str) -> str | None:
    """The system blocks (for the item `system_prompt`) or the tool definitions, each as its name and description
    (for `tool_definitions`), of the `api-request-shape` row recorded under `shape_hash`, joined by a blank line; None
    for any other row or item. The text is returned, never stored."""
    if row.get("type") != "api-request-shape" or row.get("shapeHash") != shape_hash:
        return None
    if item == "system_prompt":
        return BLOCK_SEPARATOR.join(_system_texts(row, "api-request-shape"))
    if item != "tool_definitions":
        return None
    named = []
    for tool in _shape_parts(row, "api-request-shape")[1]:
        description = tool.get("description") if isinstance(tool, dict) else None
        name = _tool_name(tool, "api-request-shape")
        named.append(f"{name}\n{description}" if isinstance(description, str) and description else name)
    return BLOCK_SEPARATOR.join(named)


def _request_tier(row: JsonObject) -> bool | None:
    """Whether the model the row's `params` names prices images at the high-resolution tier; None when the row
    has no `params`, no string `model` or a model id that is not a Claude id."""
    params = row.get("params")
    model = params.get("model") if isinstance(params, dict) else None
    return high_resolution(model) if isinstance(model, str) else None


def _request_config(row: JsonObject) -> RequestConfig:
    """The model, max tokens, thinking type and effort the row's `params` name; None for each it does not."""
    params = row.get("params")
    if not isinstance(params, dict):
        return RequestConfig()
    thinking, output = params.get("thinking"), params.get("output_config")
    thinking_type = thinking.get("type") if isinstance(thinking, dict) else None
    effort = output.get("effort") if isinstance(output, dict) else None
    model, max_tokens = params.get("model"), params.get("max_tokens")
    return RequestConfig(
        model if isinstance(model, str) else None,
        max_tokens if isinstance(max_tokens, int) and not isinstance(max_tokens, bool) else None,
        thinking_type if isinstance(thinking_type, str) else None,
        effort if isinstance(effort, str) else None,
    )


def _request(chain: RequestChain, row: JsonObject) -> RequestSize:
    what = "api-request"
    request_id = row.get("id")
    if not isinstance(request_id, str):
        raise PayloadRefused(f"{what} id is not a string")
    shape_hash = _shape_hash(row, what)
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
    if chain.texts is not None:
        del chain.trail[kept:]
        chain.trail.extend(tail)
    total = chain.prefix[kept]
    for digest in tail:
        total += chain.pool.get(digest, MessageSize())
        chain.prefix.append(total)
    return RequestSize(
        request_id,
        *shape,
        total,
        unresolved,
        chain.tool_names.get(shape_hash, ()),
        _request_tier(row),
        _request_config(row),
        chain.system_digests.get(shape_hash, ""),
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
