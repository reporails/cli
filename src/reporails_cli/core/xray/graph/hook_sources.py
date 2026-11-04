"""The hooks of a session: one source per hook name, with the commands it ran, the file that declares each command and
its latest firings."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.contract.json_value import JsonValue, as_str
from reporails_cli.core.platform.dto.events import EventRecord, is_note_kind
from reporails_cli.core.platform.dto.xray_build import Frame
from reporails_cli.core.platform.dto.xray_sources import HookCommand, HookDetail, HookRun, SourceEntry, XrayArtifact
from reporails_cli.core.platform.utils.hook_config import hook_sites, read_hook_config
from reporails_cli.core.xray.derive import frame_time, tokens_of

# The firings of one hook the page lists, the latest first kept.
FIRINGS_SHOWN = 100

# What a hook command may spell for a folder Claude Code expands before it runs the command.
_FOLDER_VARIABLES = ("${CLAUDE_PLUGIN_ROOT}", "${CLAUDE_PLUGIN_DATA}", "${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR")
_GAP = "\0"


def hook_id(label: str) -> str:
    """The source id of a hook name."""
    return f"hook:{label}"


def _holds(declared: str, ran: str) -> bool:
    """Whether the command a hook config declares is the command that ran: equal, or equal with each folder
    variable standing for whatever text the harness put there."""
    template = declared
    for variable in _FOLDER_VARIABLES:
        template = template.replace(variable, _GAP)
    if _GAP not in template:
        return declared == ran
    first, *rest = template.split(_GAP)
    if not ran.startswith(first):
        return False
    at = len(first)
    for piece in rest[:-1]:
        found = ran.find(piece, at)
        if found < 0:
            return False
        at = found + len(piece)
    return ran.endswith(rest[-1]) and len(ran) - len(rest[-1]) >= at


def _declared_commands(artifacts: Sequence[XrayArtifact], frame: Frame) -> list[tuple[str, str]]:
    """Each `(command, file)` the hook configs declare, the file as the page shows it: the listed hook config files
    and the settings files, each read once."""
    paths = dict.fromkeys(
        [*(item.path for item in artifacts if item.kind == "hook"), *(str(path) for path in frame.settings_files)]
    )
    found: list[tuple[str, str]] = []
    for path in paths:
        config = read_hook_config(Path(path))
        if config is None:
            continue
        wire = relative_wire_path(path, frame.root)
        found.extend((command, wire) for command in _commands_of(config.data))
    return found


def _commands_of(data: JsonValue) -> list[str]:
    return [command for site in hook_sites(data) if (command := as_str(site.handler.get("command")))]


def _commands(ran: Sequence[str], declared: Sequence[tuple[str, str]]) -> tuple[HookCommand, ...]:
    return tuple(
        HookCommand(command, next((file for text, file in declared if _holds(text, command)), None))
        for command in dict.fromkeys(ran)
    )


def hook_sources(records: Sequence[EventRecord], artifacts: Sequence[XrayArtifact], frame: Frame) -> list[SourceEntry]:
    """A source for each hook name the records show firing; its size is that of its largest note."""
    declared = _declared_commands(artifacts, frame)
    sizes: dict[str, int] = {}
    runs: dict[str, list[tuple[HookRun, str | None]]] = {}
    for record in records:
        entry = record.harness
        if record.event == "harness" and entry is not None and is_note_kind(entry.kind) and entry.event:
            sizes[entry.label] = max(sizes.get(entry.label, 0), tokens_of(entry.chars))
        elif record.hook is not None:
            firing = record.hook
            run = HookRun(
                firing.id,
                frame_time(frame, record),
                firing.decision,
                firing.exit_code,
                firing.duration_ms,
                firing.chars,
            )
            runs.setdefault(firing.label, []).append((run, firing.command))
    return [
        SourceEntry(
            hook_id(label),
            "hook",
            label,
            None,
            sizes.get(label),
            None,
            False,
            None,
            None,
            detail=HookDetail(
                _commands([command for _, command in fired if command], declared),
                len(fired),
                tuple(run for run, _ in fired[-FIRINGS_SHOWN:]),
            ),
        )
        for label, fired in ((label, runs.get(label, [])) for label in dict.fromkeys([*sizes, *runs]))
    ]
