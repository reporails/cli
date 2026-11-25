"""The hooks of a session: one source per hook name that fired, with the commands it ran, the file that declares each
command and its latest firings, and one per declared hook that did not fire, with whether it can."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from reporails_cli.core.platform.config.claude_settings import hooks_turned_off
from reporails_cli.core.platform.contract.json_value import as_str
from reporails_cli.core.platform.dto.events import EventRecord, HookFiring, is_note_kind
from reporails_cli.core.platform.dto.hooks import CannotFire
from reporails_cli.core.platform.dto.xray_build import Frame
from reporails_cli.core.platform.dto.xray_sources import (
    DeclaredHook,
    EarlierFirings,
    HookCommand,
    HookDetail,
    HookEarlier,
    HookHealth,
    HookRun,
    SourceEntry,
    XrayArtifact,
)
from reporails_cli.core.platform.policy.host_hooks import matcher_selects
from reporails_cli.core.platform.utils.hook_config import (
    FOLDER_VARIABLE_RE,
    cannot_fire,
    hook_script,
    hook_sites,
    read_hook_config,
)
from reporails_cli.core.platform.utils.utils import relative_wire_path
from reporails_cli.core.xray.derive import frame_time, real_path, tokens_of
from reporails_cli.core.xray.vocabulary import HOOK_STATUS_TEXT

# The firings of one hook the page lists, the latest first kept.
FIRINGS_SHOWN = 100

_GAP = "\0"


def hook_id(label: str) -> str:
    """The source id of a hook name."""
    return f"hook:{label}"


def _holds(declared: str, ran: str) -> bool:
    """Whether the command a hook config declares is the command that ran: equal, or equal with each folder
    variable standing for whatever text the harness put there."""
    template = FOLDER_VARIABLE_RE.sub(_GAP, declared)
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
        off = hooks_turned_off(frame.root, Path(real))
        off_wire = None if off is None else relative_wire_path(str(off), frame.root)
        for site in hook_sites(config.data):
            command = as_str(site.handler.get("command"))
            if command:
                place = "/".join(str(step) for step in site.path)
                found.append(DeclaredHook(site.event, site.matcher, command, wire, plugin, place, off_wire))
    return found


def _commands(ran: Sequence[str], declared: Sequence[DeclaredHook]) -> tuple[HookCommand, ...]:
    return tuple(
        HookCommand(command, next((item.file for item in declared if _holds(item.command, command)), None))
        for command in dict.fromkeys(ran)
    )


def _fits(event: str, matcher: str, command: str, firing: HookFiring) -> bool:
    """Whether a firing ran the handler registered for `event` under `matcher` with `command`: the same event, a
    matcher that selects the name the firing carries, and the command that ran."""
    tool = firing.label.partition(":")[2] if firing.label.startswith(f"{firing.event}:") else None
    return (
        firing.event == event
        and (tool is None or matcher_selects(matcher, tool))
        and (firing.command is None or _holds(command, firing.command))
    )


def _declared_for(declared: Sequence[DeclaredHook], firing: HookFiring) -> list[int]:
    """The positions of the declared handlers a firing ran: Claude Code runs every handler of the event whose matcher
    selects the tool, so a firing marks each declaration that fits it (and, when it names its command, ran it)."""
    return [at for at, item in enumerate(declared) if _fits(item.event, item.matcher, item.command, firing)]


def _recovery(item: DeclaredHook, reason: CannotFire | None, frame: Frame) -> str | None:
    if reason is None:
        return None
    if reason == "all_hooks_off":
        return None if item.hooks_off is None else f"disableAllHooks is true in {item.hooks_off}; set it to false there"
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


def _status(
    fired: Sequence[HookRun], reason: CannotFire | None, earlier: HookEarlier | None, *, checking: bool
) -> tuple[str, float | None]:
    """The phrase stating a hook's status, its `{time}`, `{when}` and `{session}` left for the page to fill, and the
    moment it last fired (seconds from the session's start; None when it did not fire this session). A hook that did
    not fire this session says when it last fired in another one, or that the other sessions are still being read."""
    moments = [run.t for run in fired if run.t is not None]
    if moments:
        return HOOK_STATUS_TEXT["fired"].format(count=len(fired), time="{time}"), max(moments)
    if earlier is not None:
        key = "earlier"
    elif checking:
        key = "checking"
    else:
        key = "never_fired" if reason is not None else "never"
    if reason is not None and key != "never_fired":
        key += "_blocked"
    why = "" if reason is None else HOOK_STATUS_TEXT[reason]
    return HOOK_STATUS_TEXT[key].format(reason=why, when="{when}", session="{session}"), None


def _reason(item: DeclaredHook, frame: Frame) -> CannotFire | None:
    """Why the declared handler cannot fire: a settings file turns every hook off, else what its script lacks."""
    if item.hooks_off is not None:
        return "all_hooks_off"
    return cannot_fire(item.command, frame.root, Path(item.plugin_root) if item.plugin_root else None)


class _HookName:
    """What the records and the hook configs say of one hook name (or of one declared handler no firing ran): its
    firings with the command each ran, its event, the positions of the declared handlers it ran as and whether some
    firing ran no declared handler."""

    def __init__(self, event: str | None = None, positions: Sequence[int] = ()) -> None:
        self.size: int | None = None
        self.runs: list[tuple[HookRun, str | None]] = []
        self.event = event
        self.positions = list(positions)
        self.undeclared = False

    def add(self, firing: HookFiring, run: HookRun, declared: Sequence[DeclaredHook]) -> list[int]:
        """Record one firing; the positions of the declared handlers it ran."""
        self.runs.append((run, firing.command))
        self.event = self.event or firing.event
        found = _declared_for(declared, firing)
        self.undeclared = self.undeclared or not found
        self.positions.extend(at for at in found if at not in self.positions)
        return found

    def detail(self, declared: Sequence[DeclaredHook], frame: Frame, own_id: str) -> HookDetail:
        """The hook's detail: its commands and firings, and for a hook a config declares its event, matcher, health and
        status. The other sessions are read later, so a declared hook that did not fire says it is still checking."""
        item = declared[self.positions[0]] if self.positions else None
        reason: CannotFire | None = None if item is None or self.runs else _reason(item, frame)
        runs = tuple(run for run, _ in self.runs)
        waiting = item is not None and not self.runs
        status, last = _status(runs, reason, None, checking=waiting)
        commands = _commands([command for _, command in self.runs if command], declared)
        if item is not None and not commands:
            commands = (HookCommand(item.command, item.file),)
        own = (own_id,) if self.undeclared or not self.positions else ()
        return HookDetail(
            commands,
            len(runs),
            runs[-FIRINGS_SHOWN:],
            self.event if item is None else item.event,
            "" if item is None else item.matcher,
            HookHealth(reason, None if item is None else _recovery(item, reason, frame)),
            status,
            last,
            None,
            waiting,
            (*(declared[position].handler for position in self.positions), *own),
        )


def hook_sources(records: Sequence[EventRecord], artifacts: Sequence[XrayArtifact], frame: Frame) -> list[SourceEntry]:
    """A source for each hook name the records show firing, its size that of its largest note, and one for each
    declared hook none of those firings ran. A hook that did not fire reads as still checking the other sessions;
    `with_earlier_firings` settles it."""
    declared = _declared_hooks(artifacts, frame)
    names: dict[str, _HookName] = {}
    ran: set[int] = set()
    for record in records:
        entry = record.harness
        if record.event == "harness" and entry is not None and is_note_kind(entry.kind) and entry.event:
            name = names.setdefault(entry.label, _HookName())
            name.size = max(name.size or 0, tokens_of(entry.chars))
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
            ran.update(names.setdefault(firing.label, _HookName()).add(firing, run, declared))
    sources = [
        _source(hook_id(label), label, name.size, name.detail(declared, frame, hook_id(label)))
        for label, name in names.items()
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
        source_id = f"hook:declared:{item.handler}"
        detail = _HookName(item.event, [at]).detail(declared, frame, source_id)
        sources.append(_source(source_id, label, None, detail))
    return sources


def _earlier_firing(detail: HookDetail, earlier: EarlierFirings) -> HookEarlier | None:
    """The latest firing in another session of the handler a declared hook's detail describes; None when none ran it."""
    if detail.event is None or not detail.commands:
        return None
    command = detail.commands[0].command
    latest = max(
        (item for item in earlier.firings if _fits(detail.event, detail.matcher, command, item.firing)),
        key=lambda item: item.moment,
        default=None,
    )
    return None if latest is None else HookEarlier(latest.session, latest.at)


def with_earlier_firings(entries: Sequence[SourceEntry], earlier: EarlierFirings) -> tuple[SourceEntry, ...]:
    """The sources with each declared hook that did not fire this session settled against what the other sessions of
    the project hold: the session and moment it last fired in, or that nothing was found, or that the read goes on."""
    settled: list[SourceEntry] = []
    for entry in entries:
        detail = entry.detail
        if not isinstance(detail, HookDetail) or detail.firing_count or detail.event is None:
            settled.append(entry)
            continue
        found = _earlier_firing(detail, earlier)
        status, _ = _status((), detail.health.cannot_fire, found, checking=earlier.checking)
        settled.append(replace(entry, detail=replace(detail, status=status, earlier=found, checking=earlier.checking)))
    return tuple(settled)


def _source(source_id: str, label: str, size: int | None, detail: HookDetail) -> SourceEntry:
    return SourceEntry(source_id, "hook", label, None, size, None, False, None, None, detail=detail)
