"""Field readers the Claude Code transcript adapter shares: a required text field, a list of strings, a meta field
of one type, the items of a delta row sized by name, a subagent's brief and a usage object's cache-write split. Each
refuses a field that is not the pinned shape."""

from __future__ import annotations

from reporails_cli.core.eventbus.adapters.claude_calls import blocks_text
from reporails_cli.core.eventbus.adapters.claude_requests import BLOCK_SEPARATOR
from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_object, opt_str, strict_str_list


def meta_field[Field: (str, int, bool)](meta: JsonObject, key: str, kind: type[Field]) -> Field | None:
    """A meta field that must be of type `kind` when present; None when absent."""
    value = meta.get(key)
    if value is None:
        return None
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise PayloadRefused(f"subagent meta {key} is not a {kind.__name__}")
    return value


def sized_by_name(
    names: list[str], items: list[str], readded: tuple[str, ...], what: str
) -> tuple[tuple[str, int], ...]:
    """Each added item's size under its name; the names and the items must pair up one to one. With no items every
    name must be one the row re-added, and none is sized."""
    if not items:
        stray = [name for name in names if name not in readded]
        if stray:
            raise PayloadRefused(
                f"{what} lists names with no items that readdedNames does not name: {', '.join(stray)}"
            )
        return ()
    if len(names) != len(items):
        raise PayloadRefused(f"{what} lists {len(names)} names for {len(items)} items")
    return tuple((name, len(item)) for name, item in zip(names, items, strict=True))


def string_list(value: JsonValue, field: str, what: str) -> list[str]:
    """The strings of a field that must be a list of strings; refuses any other value."""
    items = strict_str_list(value)
    if items is None:
        raise PayloadRefused(f"{what} {field} is not a list of strings")
    return items


def required_text(row: JsonObject, key: str, what: str) -> str:
    """The non-empty text field `key` of a row; refuses a row without it."""
    value = opt_str(row.get(key))
    if not value:
        raise PayloadRefused(f"{what} has no {key}")
    return value


def brief_text(first_row: JsonObject) -> str | None:
    """The text of a subagent file's first row, None when it holds none; refuses a first row that is not a user row."""
    if first_row.get("type") != "user":
        raise PayloadRefused("subagent file does not open with a user row")
    content = as_object(first_row.get("message")).get("content")
    if isinstance(content, str):
        return content or None
    texts = blocks_text(content, "subagent first row")
    return BLOCK_SEPARATOR.join(texts) if texts else None


def usage_counts(usage: JsonObject) -> JsonObject:
    """A row's usage object with the cache-write split lifted to the keys the usage record reads; a present
    `cache_creation` that is not an object refuses the row."""
    creation = usage.get("cache_creation")
    if creation is not None and not isinstance(creation, dict):
        raise PayloadRefused("assistant usage cache_creation is not an object")
    split = creation or {}
    return {
        **usage,
        "cache_write_5m_tokens": split.get("ephemeral_5m_input_tokens"),
        "cache_write_1h_tokens": split.get("ephemeral_1h_input_tokens"),
    }
