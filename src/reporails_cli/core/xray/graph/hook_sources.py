"""The hooks of a session: one source per hook name that fired, with the commands it ran, the file that declares each
command and its latest firings, and one per declared hook that did not fire, with whether it can."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from reporails_cli.core.platform.contract.json_value import as_str
from reporails_cli.core.platform.dto.events import EventRecord, is_note_kind
from reporails_cli.core.platform.dto.hooks import CannotFire
from reporails_cli.core.platform.dto.xray_build import Frame
from reporails_cli.core.platform.dto.xray_sources import (
    DeclaredHook,
    HookCommand,
    HookDetail,
    HookHealth,
    HookRun,
    SourceEntry,
    XrayArtifact,
)
from reporails_cli.core.platform.utils.hook_config import cannot_fire, hook_script, hook_sites, read_hook_config
from reporails_cli.core.platform.utils.utils import relative_wire_path
from reporails_cli.core.xray.derive import frame_time, real_path, tokens_of
from reporails_cli.core.xray.vocabulary import HOOK_STATUS_TEXT

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


def _plugin_root(path: Path) -> str | None:
    """The folder of the plugin a hook config file sits in: the nearest folder above it holding `.claude-plugin`."""
    return next((str(folder) for folder in path.parents if (folder / ".claude-plugin").is_dir()), None)


def _declared_hooks(artifacts: Sequence[XrayArtifact], frame: Frame) -> list[DeclaredHook]:
    """Each hook handler the hook configs declare: the listed hook config files and the settings files, each read
    once."""
    paths = dict.fromkeys(
        [*(item.path for item in artifacts if item.kind == "hook"), *(str(path) for path in frame.settings_files)]
    )
    found: list[DeclaredHook] = []
    seen: set[str] = set()
    for path in paths:
        real = real_path(path, frame.root)
        config = None if real in seen else read_hook_config(Path(real))
        seen.add(real)
        if config is None:
            continue
        wire = relative_wire_path(path, frame.root)
        plugin = _plugin_root(Path(real))
        for site in hook_sites(config.data):
            command = as_str(site.handler.get("command"))
            if command:
                place = "/".join(str(step) for step in site.path)
                found.append(DeclaredHook(site.event, site.matcher, command, wire, plugin, place))
    return found


def _commands(ran: Sequence[str], declared: Sequence[DeclaredHook]) -> tuple[HookCommand, ...]:
    return tuple(
        HookCommand(command, next((item.file for item in declared if _holds(item.command, command)), None))
        for command in dict.fromkeys(ran)
    )


def _declared_for(declared: Sequence[DeclaredHook], event: str, command: str | None) -> int | None:
    """The position of the first declared handler of `event` whose command is the one that ran."""
    if command is None:
        return None
    return next((at for at, item in enumerate(declared) if item.event == event and _holds(item.command, command)), None)


def _clock(moment: float) -> str:
    return datetime.fromtimestamp(moment).astimezone().strftime("%H:%M")


def _recovery(item: DeclaredHook, reason: CannotFire | None, frame: Frame) -> str | None:
    if reason is None:
        return None
    plugin = Path(item.plugin_root) if item.plugin_root else None
    found = hook_script(item.command, frame.root, plugin)
    if found is None:
        return None
    path = found[0]
    if reason == "not_executable":
        return f"chmod +x {path}"
    if reason == "script_missing":
        return f"{path} does not exist; restore it or fix the command"
    return f"{path.parent} does not exist; restore it or fix the command"


def _status(fired: Sequence[HookRun], reason: CannotFire | None, frame: Frame) -> tuple[str, str | None]:
    """The phrase stating a hook's status and the time it last fired (None when it did not fire this session)."""
    moments = [frame.t0 + run.t for run in fired if run.t is not None]
    if moments:
        text = _clock(max(moments))
        return HOOK_STATUS_TEXT["fired"].format(count=len(fired), time=text), text
    if reason is not None:
        return HOOK_STATUS_TEXT["never_fired"].format(reason=HOOK_STATUS_TEXT[reason]), None
    return HOOK_STATUS_TEXT["never"], None


def _detail(
    ran: Sequence[tuple[HookRun, str | None]],
    declared: Sequence[DeclaredHook],
    at: int | None,
    frame: Frame,
    event: str | None,
) -> HookDetail:
    """A hook's detail: its commands and firings, and for a hook a config declares its event, matcher, health and
    status."""
    item = declared[at] if at is not None else None
    reason: CannotFire | None = None
    if item is not None and not ran:
        reason = cannot_fire(item.command, frame.root, Path(item.plugin_root) if item.plugin_root else None)
    runs = tuple(run for run, _ in ran)
    status, last = _status(runs, reason, frame)
    commands = _commands([command for _, command in ran if command], declared)
    if item is not None and not commands:
        commands = (HookCommand(item.command, item.file),)
    return HookDetail(
        commands,
        len(runs),
        runs[-FIRINGS_SHOWN:],
        event if item is None else item.event,
        "" if item is None else item.matcher,
        HookHealth(reason, None if item is None else _recovery(item, reason, frame)),
        status,
        last,
    )


def hook_sources(records: Sequence[EventRecord], artifacts: Sequence[XrayArtifact], frame: Frame) -> list[SourceEntry]:
    """A source for each hook name the records show firing, its size that of its largest note, and one for each
    declared hook none of those firings ran."""
    declared = _declared_hooks(artifacts, frame)
    sizes: dict[str, int] = {}
    runs: dict[str, list[tuple[HookRun, str | None]]] = {}
    events: dict[str, str] = {}
    matched: dict[str, int] = {}
    ran: set[int] = set()
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
            events.setdefault(firing.label, firing.event)
            at = _declared_for(declared, firing.event, firing.command)
            if at is not None:
                matched.setdefault(firing.label, at)
                ran.add(at)
    sources = [
        _source(
            hook_id(label),
            label,
            sizes.get(label),
            _detail(fired, declared, matched.get(label), frame, events.get(label)),
        )
        for label, fired in ((label, runs.get(label, [])) for label in dict.fromkeys([*sizes, *runs]))
    ]
    sources.extend(_unfired_sources(declared, ran, frame))
    return sources


def _unfired_sources(declared: Sequence[DeclaredHook], ran: set[int], frame: Frame) -> list[SourceEntry]:
    """A source for each declared hook none of the recorded firings ran."""
    sources: list[SourceEntry] = []
    for at, item in enumerate(declared):
        if at in ran:
            continue
        label = f"{item.event}:{item.matcher}" if item.matcher else item.event
        script = hook_script(item.command, frame.root, Path(item.plugin_root) if item.plugin_root else None)
        label = f"{label} \u00b7 {script[0].name if script else item.command.split()[0]}"
        sources.append(
            _source(
                f"hook:declared:{item.file}:{item.place}",
                label,
                None,
                _detail([], declared, at, frame, item.event),
            )
        )
    return sources


def _source(source_id: str, label: str, size: int | None, detail: HookDetail) -> SourceEntry:
    return SourceEntry(source_id, "hook", label, None, size, None, False, None, None, detail=detail)
