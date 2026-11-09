"""The MCP servers a session's configuration declares, as plain data."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # annotations only: the hook path reads settings without loading the x-ray records
    from reporails_cli.core.platform.dto.xray_sources import ArtifactScope, McpState


@dataclass(frozen=True)
class McpDeclaration:
    """One MCP server a configuration file declares: its name, the scope of the file, the plugin that provides it
    (None for any other scope) and the file's absolute path."""

    name: str
    scope: ArtifactScope
    plugin: str | None
    file: str


@dataclass
class McpSeen:
    """What a session's records show of one MCP server while they are read: the name its instructions carry, their
    size in tokens, its tools with the calls each received and the last state a tool listing gave it."""

    name: str | None = None
    tokens: int | None = None
    tools: dict[str, int] = field(default_factory=dict)
    status: McpState | None = None
