"""Reading one tool call or result out of a Claude Code transcript row, for the routes that show a call's text."""

from __future__ import annotations

from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_object


def content_blocks(row: JsonObject, block_type: str) -> list[JsonObject]:
    """The blocks of the given type in a row's `message.content`; none when the content is not a list."""
    content = as_object(row.get("message")).get("content")
    if not isinstance(content, list):
        return []
    return [block for block in map(as_object, content) if block.get("type") == block_type]


def command_of(tool_input: JsonObject, name: str) -> str:
    """The string command of a tool call's input; refuses an input with none."""
    command = tool_input.get("command")
    if not isinstance(command, str):
        raise PayloadRefused(f"{name} call has no string command")
    return command


def blocks_text(content: JsonValue, what: str) -> list[str] | None:
    """The texts of a message's content: the string itself, or each `text` block's; None when it is neither."""
    if isinstance(content, str):
        return [content]
    if not isinstance(content, list):
        return None
    texts = [as_object(block).get("text") for block in content if as_object(block).get("type") == "text"]
    if not all(isinstance(text, str) for text in texts):
        raise PayloadRefused(f"{what} has a text block with no text")
    return [text for text in texts if isinstance(text, str)]


def call_command(row: JsonObject, use_id: str) -> str:
    """The command of the tool call `use_id` in an assistant row; refuses a row with no such call or a call with no
    string command."""
    for block in content_blocks(row, "tool_use"):
        if block.get("id") == use_id:
            return command_of(as_object(block.get("input")), str(block.get("name")))
    raise PayloadRefused(f"row holds no tool call {use_id}")


def call_input(row: JsonObject, use_id: str) -> JsonObject:
    """The input of the tool call `use_id` in an assistant row."""
    for block in content_blocks(row, "tool_use"):
        if block.get("id") == use_id:
            return as_object(block.get("input"))
    raise PayloadRefused(f"row holds no tool call {use_id}")


def holds_call(row: JsonObject, use_id: str) -> bool:
    """Whether `row` is an assistant row holding the tool call `use_id`."""
    return row.get("type") == "assistant" and any(
        block.get("id") == use_id for block in content_blocks(row, "tool_use")
    )


def holds_result(row: JsonObject, use_id: str) -> bool:
    """Whether `row` is a user row holding the result of the tool call `use_id`."""
    return row.get("type") == "user" and any(
        block.get("tool_use_id") == use_id for block in content_blocks(row, "tool_result")
    )


def result_text(row: JsonObject, use_id: str) -> str:
    """The text of the result of the tool call `use_id` in a user row."""
    for block in content_blocks(row, "tool_result"):
        if block.get("tool_use_id") == use_id:
            texts = blocks_text(block.get("content"), "tool_result")
            if texts is None:
                raise PayloadRefused("tool_result content is neither text nor a list of blocks")
            return "".join(texts)
    raise PayloadRefused(f"row holds no result of tool call {use_id}")
