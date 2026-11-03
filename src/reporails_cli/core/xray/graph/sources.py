"""The sources of a session: every file, MCP server and hook a context could take in, with the lookup that turns a
path, run name, server or hook label into a source id."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import MEMORY_INDEX_FILENAME
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.dto.events import EventRecord, is_note_kind
from reporails_cli.core.platform.dto.xray_build import Frame, SourceTable
from reporails_cli.core.platform.dto.xray_graph import SourceKind
from reporails_cli.core.platform.dto.xray_sources import (
    AGENT_ARTIFACT_KINDS,
    SOURCE_KIND_OF_ARTIFACT,
    MemoryRole,
    SourceEntry,
    XrayArtifact,
)
from reporails_cli.core.xray.artifacts import unlisted_loads, winners
from reporails_cli.core.xray.derive import count_for, file_tokens_est, real_path, tokens_of


def mcp_id(server: str) -> str:
    """The source id of an MCP server."""
    return f"mcp:{server}"


def hook_id(label: str) -> str:
    """The source id of a hook note label."""
    return f"hook:{label}"


def builtin_agent_id(agent_type: str) -> str:
    """The source id of a built-in agent type, which no agent definition's id can equal."""
    return f"builtin-agent:{agent_type}"


def memory_role(entry: SourceEntry) -> MemoryRole | None:
    """Whether a memory source is the memory index or an item read on demand; None for any other kind."""
    if entry.kind != "memory":
        return None
    return "index" if entry.path is not None and Path(entry.path).name == MEMORY_INDEX_FILENAME else "item"


def source_label(entry: SourceEntry) -> str:
    """The name the page shows a source by: an instruction file by its path, a rule by its file name, a memory
    item without its folder or type prefix; any other source by its name."""
    if entry.path is None:
        return entry.name
    if entry.kind == "instructions":
        return entry.path
    if entry.kind == "rule":
        return Path(entry.path).name
    if entry.kind == "memory" and entry.name == entry.path:
        return Path(entry.path).name if memory_role(entry) == "index" else Path(entry.path).stem
    return entry.name


def for_path(table: SourceTable, path: str) -> str | None:
    """The id of the source the file at `path` is, or None when it is no source."""
    return table.by_real.get(real_path(path, table.root))


def _unlisted_loads(records: Sequence[EventRecord], known: Mapping[str, str], frame: Frame) -> list[SourceEntry]:
    """A source for each loaded instruction file the listing does not hold."""
    return [
        SourceEntry(
            wire := relative_wire_path(item.path, frame.root),
            SOURCE_KIND_OF_ARTIFACT[item.kind],
            wire,
            wire,
            file_tokens_est(item.path),
            count_for(frame.findings, item.path, frame.root),
            False,
            None,
            None,
        )
        for item in unlisted_loads(records, known, frame.root)
    ]


def _harness_sources(records: Sequence[EventRecord]) -> list[SourceEntry]:
    """A source for each MCP server the records name and each hook note label; a hook's size is that of its
    largest firing."""
    servers: dict[str, int | None] = {}
    called: dict[str, dict[str, int]] = {}
    hooks: dict[str, int] = {}
    for record in records:
        entry = record.harness
        if record.event == "harness" and entry is not None and entry.kind == "mcp_instructions":
            for name, chars in entry.added:
                servers[name] = tokens_of(chars)
        elif record.event == "harness" and entry is not None and is_note_kind(entry.kind) and entry.event:
            hooks[entry.label] = max(hooks.get(entry.label, 0), tokens_of(entry.chars))
        elif record.event == "tool_call" and record.tool is not None and record.tool.server:
            servers.setdefault(record.tool.server, None)
            counts = called.setdefault(record.tool.server, {})
            counts[record.tool.name or "tool"] = counts.get(record.tool.name or "tool", 0) + 1
    found = [
        SourceEntry(
            mcp_id(name),
            "mcp",
            name,
            None,
            size,
            None,
            False,
            None,
            None,
            tools=tuple(sorted(called.get(name, {}).items(), key=lambda item: (-item[1], item[0]))),
        )
        for name, size in servers.items()
    ]
    found.extend(
        SourceEntry(hook_id(label), "hook", label, None, size, None, False, None, None) for label, size in hooks.items()
    )
    return found


def _unrecorded_kinds(records: Sequence[EventRecord]) -> frozenset[SourceKind]:
    """The kinds whose loads the records cannot show: instruction files when no record of the session is an
    instruction load (an older transcript carries none)."""
    return frozenset() if any(record.event == "instruction_load" for record in records) else frozenset({"instructions"})


def build_sources(artifacts: Sequence[XrayArtifact], records: Sequence[EventRecord], frame: Frame) -> SourceTable:
    """The session's sources: each listed file that can enter a context, each loaded file the listing misses, each
    MCP server seen and each hook note label."""
    # Of two agent definitions sharing a type name only the one the harness resolves to is a source.
    agent_winners = {item.path for item in winners(artifacts, AGENT_ARTIFACT_KINDS).values()}
    listed = [
        item
        for item in artifacts
        if item.kind in SOURCE_KIND_OF_ARTIFACT
        and (item.kind not in AGENT_ARTIFACT_KINDS or item.path in agent_winners)
    ]
    entries = [
        SourceEntry(
            item.path,
            SOURCE_KIND_OF_ARTIFACT[item.kind],
            item.label,
            item.path,
            item.tokens_est,
            item.findings,
            item.actionable,
            item.advertised,
            item.linked,
            item.scopes,
        )
        for item in listed
    ]
    by_real = {real_path(item.path, frame.root): item.path for item in listed}
    entries.extend(_unlisted_loads(records, by_real, frame))
    by_real.update({real_path(entry.path, frame.root): entry.id for entry in entries if entry.path is not None})
    by_run = {
        name: by_real[real_path(path, frame.root)]
        for name, path in frame.runnable.items()
        if real_path(path, frame.root) in by_real
    }
    entries.extend(_harness_sources(records))
    return SourceTable(tuple(entries), frame.root, by_real, by_run, _unrecorded_kinds(records))


def ran_sources(records: Sequence[EventRecord], table: SourceTable) -> set[str]:
    """The ids of the skill and command sources any agent ran, a forked run included."""
    return {
        table.by_run[record.skill.name]
        for record in records
        if record.event == "skill_run" and record.skill is not None and record.skill.name in table.by_run
    }
