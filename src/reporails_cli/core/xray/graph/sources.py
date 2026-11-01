"""The sources of a session: every file, MCP server and hook a context could take in, with the lookup that turns a
path, run name, server or hook label into a source id."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.dto.events import EventRecord, is_note_kind
from reporails_cli.core.platform.dto.xray import SOURCE_KIND_OF_ARTIFACT, SourceEntry, XrayArtifact
from reporails_cli.core.platform.dto.xray_graph import SourceKind
from reporails_cli.core.xray.derive import BYTES_PER_TOKEN, Frame, count_for, file_tokens_est, real_path

# The memory type an auto-memory file is loaded as.
AUTO_MEMORY_TYPE = "AutoMem"


def mcp_id(server: str) -> str:
    """The source id of an MCP server."""
    return f"mcp:{server}"


def hook_id(label: str) -> str:
    """The source id of a hook note label."""
    return f"hook:{label}"


@dataclass(frozen=True)
class SourceTable:
    """The sources in listing order, with the lookups from a file path or a skill or command name to its id."""

    entries: tuple[SourceEntry, ...]
    root: Path
    by_real: Mapping[str, str]
    by_run: Mapping[str, str]

    def get(self, source_id: str) -> SourceEntry | None:
        """The source with id `source_id`, or None when the session has none."""
        return next((entry for entry in self.entries if entry.id == source_id), None)

    def for_path(self, path: str) -> str | None:
        """The id of the source the file at `path` is, or None when it is no source."""
        return self.by_real.get(real_path(path, self.root))


def _unlisted_loads(records: Sequence[EventRecord], known: Mapping[str, str], frame: Frame) -> list[SourceEntry]:
    """A source for each loaded instruction file the listing does not hold."""
    seen = set(known)
    found: list[SourceEntry] = []
    for record in records:
        if record.event != "instruction_load" or record.load is None:
            continue
        resolved = real_path(record.load.path, frame.root)
        if resolved in seen:
            continue
        seen.add(resolved)
        wire = relative_wire_path(record.load.path, frame.root)
        kind: SourceKind = "memory" if record.load.memory_type == AUTO_MEMORY_TYPE else "instructions"
        found.append(
            SourceEntry(
                wire,
                kind,
                wire,
                wire,
                file_tokens_est(record.load.path),
                count_for(frame.findings, record.load.path, frame.root),
                False,
                None,
                None,
            )
        )
    return found


def _harness_sources(records: Sequence[EventRecord]) -> list[SourceEntry]:
    """A source for each MCP server the records name and each hook note label."""
    servers: dict[str, int | None] = {}
    hooks: dict[str, int] = {}
    for record in records:
        entry = record.harness
        if record.event == "harness" and entry is not None and entry.kind == "mcp_instructions":
            for name, chars in entry.added:
                servers[name] = chars // BYTES_PER_TOKEN
        elif record.event == "harness" and entry is not None and is_note_kind(entry.kind) and entry.event:
            hooks[entry.label] = hooks.get(entry.label, 0) + entry.chars // BYTES_PER_TOKEN
        elif record.event == "tool_call" and record.tool is not None and record.tool.server:
            servers.setdefault(record.tool.server, None)
    found = [
        SourceEntry(mcp_id(name), "mcp", name, None, size, None, False, None, None) for name, size in servers.items()
    ]
    found.extend(
        SourceEntry(hook_id(label), "hook", label, None, size, None, False, None, None) for label, size in hooks.items()
    )
    return found


def build_sources(artifacts: Sequence[XrayArtifact], records: Sequence[EventRecord], frame: Frame) -> SourceTable:
    """The session's sources: each listed file that can enter a context, each loaded file the listing misses, each
    MCP server seen and each hook note label."""
    listed = [item for item in artifacts if item.kind in SOURCE_KIND_OF_ARTIFACT]
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
    return SourceTable(tuple(entries), frame.root, by_real, by_run)


def ran_sources(records: Sequence[EventRecord], table: SourceTable) -> set[str]:
    """The ids of the skill and command sources any agent ran, a forked run included."""
    return {
        table.by_run[record.skill.name]
        for record in records
        if record.event == "skill_run" and record.skill is not None and record.skill.name in table.by_run
    }
