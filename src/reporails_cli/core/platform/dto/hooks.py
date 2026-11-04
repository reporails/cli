"""A hook config file and the handlers it registers."""

from __future__ import annotations

from dataclasses import dataclass

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue

# A data path from the top of the parsed file to one handler: keys and list positions.
HookPath = tuple[str | int, ...]


@dataclass(frozen=True)
class HookSite:
    """One hook handler: its event, the matcher it is registered under, the handler and its data path."""

    event: str
    matcher: str
    handler: JsonObject
    path: HookPath


@dataclass(frozen=True)
class HookConfig:
    """A hook config file read once: its text and the data parsed from it."""

    text: str
    data: JsonValue
