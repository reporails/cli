"""The JSON value types and the readers of an optional field of a parsed document.

A required field is validated by the record that reads it, not by these readers.
"""

from __future__ import annotations

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]

# A value of the request document: JSON values plus the raw bytes of a packed embedding.
type WireValue = JsonScalar | bytes | list[WireValue] | dict[str, WireValue]
type WireObject = dict[str, WireValue]


def as_object(value: JsonValue) -> JsonObject:
    """The object an optional field of a parsed document holds, `{}` when it is not one."""
    return value if isinstance(value, dict) else {}


def as_list(value: JsonValue) -> list[JsonValue]:
    """The list an optional field of a parsed document holds, or `[]` when it is not one."""
    return value if isinstance(value, list) else []


def wire_list(value: WireValue | None) -> list[WireValue]:
    """The list a request field holds, `[]` when it is absent or not a list."""
    return value if isinstance(value, list) else []


def as_str(value: JsonValue) -> str:
    """The string an optional field of a parsed document holds, or `""` when it is not one."""
    return value if isinstance(value, str) else ""


def as_int(value: JsonValue, default: int) -> int:
    """The integer (not a bool) an optional field of a parsed document holds, else `default`."""
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def opt_int(value: JsonValue) -> int | None:
    """The integer (not a bool) an optional field of a parsed document holds, else `None`."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def str_list(value: JsonValue) -> list[str]:
    """The string items of the list an optional field of a parsed document holds, `[]` when it is not a list."""
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def pattern_list(value: JsonValue) -> list[str]:
    """The patterns a file type or scope declares under one key: a single pattern as a list, a list's text items."""
    return [value] if isinstance(value, str) else str_list(value)
