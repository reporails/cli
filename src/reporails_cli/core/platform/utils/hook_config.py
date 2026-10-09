"""Where the hooks sit in a parsed hook config, as plain data.

A hook config nests its handlers in a known place: a block of events, each event a
list, each list entry a handler or a group of handlers sharing a matcher. This module
walks that shape over already-parsed data and nowhere else; reading and parsing the
file goes through `read_hook_config`, the one reader.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# A config file larger than this is not read.
MAX_HOOK_CONFIG_BYTES = 1_048_576

# A data path from the top of the parsed file to one handler: keys and list positions.
HookPath = tuple[str | int, ...]


@dataclass(frozen=True)
class HookSite:
    """One hook handler: its event, the matcher it is registered under, the handler and its data path."""

    event: str
    matcher: str
    handler: dict[str, Any]
    path: HookPath


def value_at(data: Any, path: HookPath) -> Any:
    """The value at ``path`` in parsed data, or None when the path does not exist."""
    for step in path:
        if not isinstance(data, list if isinstance(step, int) else dict):
            return None
        try:
            data = data[step]
        except (KeyError, IndexError):
            return None
    return data


def _matcher_of(holder: dict[str, Any]) -> str:
    """The matcher an entry or group carries; empty when it has none or it is not text."""
    matcher = holder.get("matcher")
    return matcher if isinstance(matcher, str) else ""


def _event_sites(event: str, entries: list[Any], where: HookPath, grouped: bool) -> Iterator[HookSite]:
    """The handlers one event lists: its entries, or the members of each entry's ``hooks`` list."""
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        members = entry.get("hooks") if grouped else None
        if not isinstance(members, list):
            yield HookSite(event, _matcher_of(entry), entry, (*where, index))
            continue
        for position, member in enumerate(members):
            if isinstance(member, dict):
                yield HookSite(event, _matcher_of(entry), member, (*where, index, "hooks", position))


def walk_hooks(data: Any, *, block: str = "", named_hooks: bool = False, grouped: bool = False) -> Iterator[HookSite]:
    """Each hook handler the parsed file declares.

    ``block`` is the top-level key holding the hooks (empty: the top-level object is the
    block). ``named_hooks``: the block maps a hook name to that hook's own events.
    ``grouped``: an entry holding a ``hooks`` list is a matcher group and that list holds
    the handlers; any other entry is itself a handler.
    """
    where: HookPath = (block,) if block else ()
    block_data = value_at(data, where)
    if not isinstance(block_data, dict):
        return
    if named_hooks:
        event_maps = [((*where, name), events) for name, events in block_data.items()]
    else:
        event_maps = [(where, block_data)]
    for map_path, events in event_maps:
        if not isinstance(events, dict):
            continue
        for event, entries in events.items():
            if isinstance(entries, list):
                yield from _event_sites(str(event), entries, (*map_path, event), grouped)


def hook_sites(data: Any) -> Iterator[HookSite]:
    """Every hook handler in a hook config of any agent, whichever shape it is written in.

    The hooks sit under a top-level ``hooks`` key when there is one, else the top-level
    object is the block. A block whose values are objects names its hooks; one whose values
    are lists maps events directly. A matcher group's ``hooks`` list is read as handlers.
    """
    if not isinstance(data, dict):
        return
    block = "hooks" if isinstance(data.get("hooks"), dict) else ""
    members = data["hooks"] if block else data
    named = any(isinstance(value, dict) for value in members.values())
    yield from walk_hooks(data, block=block, named_hooks=named, grouped=True)


class _Located(dict[str, Any]):
    """A parsed JSON object that remembers the line its opening brace is on."""

    line: int = 0


_JSON_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\n]')


def _object_lines(text: str) -> Iterator[int]:
    """The line of each JSON object's opening brace, in the order the objects close."""
    line = 1
    open_lines: list[int] = []
    for token in _JSON_TOKEN_RE.finditer(text):
        char = token.group()
        if char == "\n":
            line += 1
        elif char == "{":
            open_lines.append(line)
        elif char == "}" and open_lines:
            yield open_lines.pop()


def _load_json(text: str) -> Any:
    """Parse JSON; every object in the result knows the line it starts on."""
    lines = _object_lines(text)

    def located(pairs: list[tuple[str, Any]]) -> _Located:
        # The decoder completes objects in the order their closing braces appear.
        obj = _Located(pairs)
        obj.line = next(lines, 0)
        return obj

    return json.loads(text, object_pairs_hook=located)


@dataclass(frozen=True)
class HookConfig:
    """A hook config file read once: its text and the data parsed from it."""

    text: str
    data: Any


def read_hook_config(path: Path) -> HookConfig | None:
    """The hook config at ``path`` parsed (TOML by its suffix, else JSON, every JSON object knowing its line).

    None when the file is unreadable, larger than ``MAX_HOOK_CONFIG_BYTES``, or not valid JSON / TOML.
    """
    try:
        if path.stat().st_size > MAX_HOOK_CONFIG_BYTES:
            return None
        text = path.read_text(encoding="utf-8-sig")
        return HookConfig(text, tomllib.loads(text) if path.suffix == ".toml" else _load_json(text))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
