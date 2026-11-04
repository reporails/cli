"""The MCP servers of a session: one source per server, merging what the configuration declares, what the
instructions rows and tool listings name and which tools the agent called."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from reporails_cli.core.eventbus.adapters.claude_calls import mcp_server
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.dto.events import EventRecord, HarnessEntry
from reporails_cli.core.platform.dto.mcp import McpDeclaration, McpSeen
from reporails_cli.core.platform.dto.xray_build import Frame
from reporails_cli.core.platform.dto.xray_sources import McpDetail, McpState, SourceEntry
from reporails_cli.core.xray.derive import tokens_of

PLUGIN_SERVER_PREFIX = "plugin:"
_SLUG_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


def mcp_slug(name: str) -> str:
    """The server part Claude Code writes into a tool name `mcp__<server>__<tool>`: the server's name with every
    character outside letters, digits, `_` and `-` replaced by `_`, which turns the plugin server
    `plugin:<plugin>:<server>` into `plugin_<plugin>_<server>`."""
    return "".join(char if char in _SLUG_CHARS else "_" for char in name)


def mcp_id(server: str) -> str:
    """The source id of an MCP server, from its name or its tool-name slug."""
    return f"mcp:{mcp_slug(server)}"


def _plugin_slug(plugin: str, server: str) -> str:
    return mcp_slug(f"{PLUGIN_SERVER_PREFIX}{plugin}:{server}")


def _listing(seen: dict[str, McpSeen], entry: HarnessEntry) -> None:
    """Fold one tool listing row into `seen`: the tools it adds and removes and the servers it names as pending or
    failed."""
    for tool in (*(name for name, _ in entry.added), *entry.readded):
        server = mcp_server(tool)
        if server is not None:
            found = seen.setdefault(mcp_slug(server), McpSeen())
            found.tools.setdefault(tool, 0)
            found.status = "connected"
    for tool in entry.removed:
        server = mcp_server(tool)
        if server is not None:
            seen.setdefault(mcp_slug(server), McpSeen()).tools.pop(tool, None)
    for name in entry.pending:
        seen.setdefault(mcp_slug(name), McpSeen()).status = "pending"
    for name in entry.failed:
        seen.setdefault(mcp_slug(name), McpSeen()).status = "failed"


def _seen_servers(records: Sequence[EventRecord]) -> dict[str, McpSeen]:
    """Each server the records name by its slug: the name its instructions carry, their size, the tools its listings
    add and the calls its tools received, and the last state a listing row gave it."""
    seen: dict[str, McpSeen] = {}
    for record in records:
        entry = record.harness
        if record.event == "harness" and entry is not None and entry.kind == "mcp_instructions":
            for name, chars in entry.added:
                found = seen.setdefault(mcp_slug(name), McpSeen())
                found.name, found.tokens, found.status = name, tokens_of(chars), "connected"
        elif record.event == "harness" and entry is not None and entry.kind == "deferred_tools":
            _listing(seen, entry)
        elif record.event == "tool_call" and record.tool is not None and record.tool.server:
            found = seen.setdefault(mcp_slug(record.tool.server), McpSeen())
            tool = record.tool.name or "tool"
            found.tools[tool] = found.tools.get(tool, 0) + 1
            found.status = "connected"
    return seen


def _declared(declarations: Sequence[McpDeclaration]) -> dict[str, McpDeclaration]:
    """Each declared server by its slug; the first declaration of a slug wins, in the order the configuration is
    read."""
    found: dict[str, McpDeclaration] = {}
    for item in declarations:
        slug = _plugin_slug(item.plugin, item.name) if item.plugin else mcp_slug(item.name)
        found.setdefault(slug, item)
    return found


def _off_only(slug: str, entry: str) -> tuple[str, str | None] | None:
    """`(name, plugin)` of a turned-off entry that names a server no file declares, when the entry is a plugin's
    `plugin:<plugin>:<server>` or a claude.ai connector; None for a bare name."""
    if entry.startswith(PLUGIN_SERVER_PREFIX):
        _, _, rest = entry.partition(PLUGIN_SERVER_PREFIX)
        plugin, _, server = rest.partition(":")
        return (server or entry, plugin or None)
    return (entry, None) if slug.startswith("claude_ai_") else None


def _state(seen: McpSeen | None, *, off: bool) -> McpState:
    if seen is not None and seen.status is not None:
        return seen.status
    return "turned_off" if off else "declared"


def mcp_sources(records: Sequence[EventRecord], frame: Frame) -> list[SourceEntry]:
    """A source for each MCP server the session or the configuration names, merged by the server's tool-name slug."""
    seen = _seen_servers(records)
    declared = _declared(frame.mcp)
    off = {mcp_slug(entry): entry for entry in frame.mcp_off}
    slugs = [*declared, *(slug for slug in seen if slug not in declared)]
    slugs += [slug for slug, entry in off.items() if slug not in slugs and _off_only(slug, entry) is not None]
    return [_source(slug, seen.get(slug), declared.get(slug), off.get(slug), frame.root) for slug in slugs]


def _source(
    slug: str, seen: McpSeen | None, declaration: McpDeclaration | None, off: str | None, root: Path
) -> SourceEntry:
    plugin = declaration.plugin if declaration is not None else None
    name = declaration.name if declaration is not None else seen.name if seen and seen.name else slug
    if declaration is None and seen is None and off is not None:
        named = _off_only(slug, off)
        name, plugin = named if named is not None else (off, None)
    tools = tuple(sorted(seen.tools.items(), key=lambda item: (-item[1], item[0]))) if seen else ()
    detail = McpDetail(
        plugin,
        declaration.scope if declaration is not None else None,
        relative_wire_path(declaration.file, root) if declaration is not None else None,
        _state(seen, off=off is not None),
    )
    size = seen.tokens if seen is not None else None
    return SourceEntry(mcp_id(slug), "mcp", name, None, size, None, False, None, None, tools=tools, detail=detail)
