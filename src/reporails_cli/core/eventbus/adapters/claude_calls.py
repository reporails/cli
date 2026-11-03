"""Reading one tool call or result out of a Claude Code transcript row, for the routes that show a call's text."""

from __future__ import annotations

import hashlib

from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_object
from reporails_cli.core.platform.dto.events import TARGETS_FILE, ToolCategory, ToolUse

MCP_PREFIX = "mcp__"
MCP_SEPARATOR = "__"
FINGERPRINT_CHARS = 16
# How the result of a launched background agent opens: an acknowledgement, not the agent's answer.
LAUNCH_ACK_PREFIX = "Async agent launched"
# The tool names of each category the side track and the inspector group by; an MCP tool is told by its prefix.
TOOL_CATEGORY: dict[str, ToolCategory] = {
    **dict.fromkeys(("Read", "Grep", "Glob", "LS", "NotebookRead", "WebFetch", "WebSearch"), "read"),
    **dict.fromkeys(("Edit", "MultiEdit", "Write", "NotebookEdit"), "edit"),
    **dict.fromkeys(("Bash", "PowerShell"), "run"),
    **dict.fromkeys(("Agent", "Task"), "agent"),
    "SubagentHandback": "handback",
}
PATH_KEYS = ("file_path", "notebook_path", "path")


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


def mcp_server(name: str) -> str | None:
    """The server of an `mcp__<server>__<tool>` tool name; None for any other name."""
    if not name.startswith(MCP_PREFIX):
        return None
    server = name.removeprefix(MCP_PREFIX).split(MCP_SEPARATOR, 1)[0]
    return server or None


def tool_category(name: str) -> ToolCategory:
    """The category a tool name falls in."""
    if mcp_server(name) is not None:
        return "mcp"
    return TOOL_CATEGORY.get(name, "other")


def _call_path(tool_input: JsonObject) -> str | None:
    for key in PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
    return None


def tool_call(block: JsonObject) -> ToolUse:
    """The call one `tool_use` block makes; refuses a block without string `id` and `name` or an object `input`."""
    use_id, name, tool_input = block.get("id"), block.get("name"), block.get("input")
    if not isinstance(use_id, str) or not isinstance(name, str):
        raise PayloadRefused("tool_use block has no string id and name")
    if not isinstance(tool_input, dict):
        raise PayloadRefused(f"{name} call input is not an object")
    category = tool_category(name)
    path = _call_path(tool_input) if TARGETS_FILE[category] else None
    chars: int | None = None
    fingerprint: str | None = None
    if category == "handback":
        message = tool_input.get("message")
        if not isinstance(message, str):
            raise PayloadRefused("SubagentHandback call has no string message")
        chars = len(message)
    elif category == "run":
        fingerprint = hashlib.sha256(command_of(tool_input, name).encode()).hexdigest()[:FINGERPRINT_CHARS]
    return ToolUse(name, use_id, path, server=mcp_server(name), category=category, chars=chars, fingerprint=fingerprint)


def tool_result(block: JsonObject) -> ToolUse:
    """The result one `tool_result` block reports: its call id, the size of its content and whether it failed."""
    use_id, failed = block.get("tool_use_id"), block.get("is_error")
    if not isinstance(use_id, str):
        raise PayloadRefused("tool_result block has no string tool_use_id")
    if failed is not None and not isinstance(failed, bool):
        raise PayloadRefused("tool_result is_error is not a boolean")
    texts = blocks_text(block.get("content"), "tool_result")
    if texts is None:
        raise PayloadRefused("tool_result content is neither text nor a list of blocks")
    return ToolUse(
        use_id=use_id,
        chars=sum(len(text) for text in texts),
        error=bool(failed),
        launch_ack=next((text for text in texts if text), "").startswith(LAUNCH_ACK_PREFIX),
    )
