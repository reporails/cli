"""Turn one session's event records into loads, turns and subagent runs."""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.dto.events import (
    DELTA_KINDS,
    TURN_HELD_KINDS,
    EventRecord,
    HarnessEntry,
    HarnessKind,
    TokenUsage,
    is_note_kind,
)
from reporails_cli.core.platform.dto.xray import (
    LOAD_KIND_OF_MEMORY_TYPE,
    CompactionTrigger,
    XrayCompaction,
    XrayHarnessItem,
    XrayLoad,
    XrayNote,
    XrayPrompt,
    XrayRun,
    XraySubagent,
    XrayTurn,
)

# How many bytes of file text one token stands for in a size estimate.
BYTES_PER_TOKEN = 4


def epoch(text: str) -> float | None:
    """Seconds since 1970 of an ISO-8601 time (a trailing `Z` is UTC), or None when it does not parse."""
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).timestamp()


def context_of(usage: TokenUsage) -> int:
    """The context one reply carried: fresh input, cache writes and cache reads."""
    return usage.input_tokens + usage.cache_creation_input_tokens + usage.cache_read_input_tokens


def real_path(path: str, root: Path) -> str:
    """The resolved path a shown or absolute path names, for comparing two names of one file."""
    return str(safe_resolve(root / Path(path).expanduser()))


def count_for(findings: Mapping[str, int], path: str, root: Path) -> int | None:
    """The finding count held for a file, by its absolute or project-relative path; None when none is held."""
    if path in findings:
        return findings[path]
    try:
        return findings.get(Path(path).relative_to(root).as_posix())
    except ValueError:
        return None


@dataclass(frozen=True)
class Frame:
    """What a derivation reads beside the records: the session's first time, the project, its findings and the
    files a run name can stand for."""

    t0: float
    root: Path
    findings: Mapping[str, int]
    # Absolute path of the skill or command file each run name stands for.
    runnable: Mapping[str, str]

    def at(self, record: EventRecord) -> float | None:
        """Seconds from the session's first transcript record to `record`, None for an unparsable time."""
        moment = epoch(record.time)
        return None if moment is None else moment - self.t0


def file_tokens_est(path: str) -> int | None:
    """The file's size in tokens, estimated from its bytes; None when it is not a readable file."""
    try:
        target = Path(path)
        return target.stat().st_size // BYTES_PER_TOKEN if target.is_file() else None
    except OSError:
        return None


def loads_of(records: Sequence[EventRecord], frame: Frame) -> tuple[XrayLoad, ...]:
    """One load of each `instruction_load` record, sized from the file on disk."""
    return tuple(
        XrayLoad(
            path=relative_wire_path(record.load.path, frame.root),
            kind=LOAD_KIND_OF_MEMORY_TYPE.get(record.load.memory_type or "", "other"),
            t=frame.at(record),
            tokens_est=file_tokens_est(record.load.path),
            findings=count_for(frame.findings, record.load.path, frame.root),
        )
        for record in records
        if record.event == "instruction_load" and record.load is not None
    )


@dataclass
class _Bucket:
    """What one turn gathered."""

    replies: list[tuple[float, int]] = field(default_factory=list)
    loads: list[EventRecord] = field(default_factory=list)
    reads: list[str] = field(default_factory=list)
    runs: list[str] = field(default_factory=list)
    skill_runs: list[XrayRun] = field(default_factory=list)
    prompts: list[XrayPrompt] = field(default_factory=list)
    notes: list[XrayNote] = field(default_factory=list)
    compaction: EventRecord | None = None
    last_time: float = 0.0


@dataclass(frozen=True)
class Replies:
    """The main session's replies in time order: (time, context)."""

    points: tuple[tuple[float, int], ...]

    def before(self, t: float) -> int | None:
        """The context of the last reply at or before `t`."""
        found = [context for moment, context in self.points if moment <= t]
        return found[-1] if found else None

    def after(self, t: float) -> int | None:
        """The context of the first reply at or after `t`."""
        return next((context for moment, context in self.points if moment >= t), None)


def main_replies(records: Sequence[EventRecord]) -> Replies:
    """The main session's `assistant_usage` records as (time, context), in time order."""
    points = [
        (moment, context_of(record.usage))
        for record in records
        if record.event == "assistant_usage" and record.subagent_id is None and record.usage is not None
        if (moment := epoch(record.time)) is not None
    ]
    return Replies(tuple(sorted(points)))


def _compaction(post: EventRecord, replies: Replies, t0: float) -> XrayCompaction | None:
    moment = epoch(post.time)
    if moment is None:
        return None
    trigger: CompactionTrigger | None = (
        "manual" if post.source == "manual" else "auto" if post.source == "auto" else None
    )
    before, after = replies.before(moment), replies.after(moment)
    return XrayCompaction(t=moment - t0, trigger=trigger, before=before, after=after)


def turn_end_times(records: Sequence[EventRecord]) -> list[float]:
    """The times of the main session's `turn_end` records, in time order."""
    return sorted(
        moment
        for record in records
        if record.event == "turn_end" and record.subagent_id is None and (moment := epoch(record.time)) is not None
    )


def turn_index(moment: float, ends: Sequence[float]) -> int:
    """The 0-based turn a time falls in: turn n spans the time after turn n-1's end up to and including its own."""
    return bisect_left(ends, moment)


def start_loads(records: Sequence[EventRecord], replies: Replies) -> list[EventRecord]:
    """The main session's loads timed before its first reply."""
    first = replies.points[0][0] if replies.points else float("inf")
    return [
        record
        for record in records
        if record.event == "instruction_load"
        and record.subagent_id is None
        and (moment := epoch(record.time)) is not None
        and moment < first
    ]


def start_notes(records: Sequence[EventRecord], replies: Replies) -> list[EventRecord]:
    """The main session's session-start hook notes timed before its first reply."""
    first = replies.points[0][0] if replies.points else float("inf")
    return [
        record
        for record in records
        if record.harness is not None
        and record.harness.kind == "hook_note"
        and record.harness.event == "SessionStart"
        and record.subagent_id is None
        and (moment := epoch(record.time)) is not None
        and moment < first
    ]


@dataclass
class _Slot:
    """One harness item as it is summed: its count and size, the size of each item present that a delta row
    added, and the size each name last had."""

    kind: HarnessKind
    label: str
    count: int | None
    chars: int
    sizes: dict[str, int] = field(default_factory=dict)
    known: dict[str, int] = field(default_factory=dict)

    @classmethod
    def of(cls, entry: HarnessEntry) -> _Slot:
        """The slot a kind's first record opens."""
        sizes = {**dict(entry.added), **dict.fromkeys(entry.readded, 0)}
        return cls(entry.kind, entry.label, entry.count, entry.chars, sizes, dict(sizes))

    def add(self, entry: HarnessEntry) -> None:
        """Fold in a later delta row of the same kind: the size of each name it removed leaves, its own added items
        arrive, and a name it re-added keeps the size it has, or takes the size it last had when it had left."""
        present = sum(1 for name in entry.readded if name in self.sizes)
        revived = [name for name in entry.readded if name not in self.sizes]
        delta = (entry.count or 0) - present
        self.count = None if self.count is None and entry.count is None else (self.count or 0) + delta
        self.chars += entry.chars - sum(self.sizes.pop(name, 0) for name in entry.removed)
        self.sizes.update(entry.added)
        self.known.update(entry.added)
        for name in revived:
            self.sizes[name] = self.known.get(name, 0)
            self.chars += self.sizes[name]


def build_harness(records: Sequence[EventRecord], replies: Replies) -> tuple[XrayHarnessItem, ...] | None:
    """The harness's own context in the main session: the first record of each kind, a list kind's delta rows
    summed up to the first compaction, and every session-start hook note timed before the first reply; None
    when the records hold no harness record."""
    started = {id(record) for record in start_notes(records, replies)}
    slots: list[_Slot] = []
    by_kind: dict[str, _Slot] = {}
    compacted = False
    for record in records:
        if record.subagent_id is not None:
            continue
        entry = record.harness
        if record.event == "post_compact":
            compacted = True
        elif record.event != "harness" or entry is None:
            continue
        elif is_note_kind(entry.kind):
            if id(record) in started:
                slots.append(_Slot.of(entry))
        elif entry.kind not in by_kind:
            by_kind[entry.kind] = _Slot.of(entry)
            slots.append(by_kind[entry.kind])
        elif entry.kind in DELTA_KINDS and not compacted:
            by_kind[entry.kind].add(entry)
    items = [XrayHarnessItem(slot.kind, slot.label, slot.count, slot.chars // BYTES_PER_TOKEN) for slot in slots]
    return tuple(items) if items else None


def _bucket_of(buckets: dict[int, _Bucket], record: EventRecord, ends: Sequence[float]) -> _Bucket | None:
    moment = epoch(record.time)
    if moment is None:
        return None
    found = buckets.setdefault(turn_index(moment, ends), _Bucket())
    found.last_time = max(found.last_time, moment)
    return found


def _gather_transcript(
    buckets: dict[int, _Bucket], records: Sequence[EventRecord], ends: Sequence[float], skip: set[int], frame: Frame
) -> None:
    for record in records:
        if id(record) in skip:
            continue
        if record.subagent_id is not None and record.event != "subagent_run":
            continue
        if not _bears_turn(record):
            continue
        target = _bucket_of(buckets, record, ends)
        if target is not None:
            _file_in_turn(target, record, frame)


def _file_in_turn(target: _Bucket, record: EventRecord, frame: Frame) -> None:
    """Put a turn-bearing record where its kind belongs in the turn."""
    if record.event == "post_compact":
        if target.compaction is None:
            target.compaction = record
    elif record.event == "harness":
        _gather_note(target, record, frame)
    elif record.event == "prompt_submit" and record.prompt is not None:
        prompt = record.prompt
        target.prompts.append(XrayPrompt(prompt.id, frame.at(record) or 0.0, prompt.chars, prompt.queued))
    elif record.event == "assistant_usage" and record.usage is not None:
        target.replies.append((frame.at(record) or 0.0, context_of(record.usage)))
    elif record.event == "instruction_load":
        target.loads.append(record)
    elif record.event == "subagent_run" and record.subagent_id is not None:
        target.runs.append(record.subagent_id)
    elif record.event == "skill_run" and record.skill is not None:
        target.skill_runs.append(_skill_run(record, frame))


def _skill_run(record: EventRecord, frame: Frame) -> XrayRun:
    skill = record.skill
    if skill is None:
        raise ValueError("record names no skill run")
    moment = frame.at(record) or 0.0
    path = frame.runnable.get(skill.name)
    if path is None:
        return XrayRun(skill.name, moment, skill.forked, None, None)
    return XrayRun(skill.name, moment, skill.forked, relative_wire_path(path, frame.root), file_tokens_est(path))


def _bears_turn(record: EventRecord) -> bool:
    """Whether a record is something a turn holds (a reply, load, prompt, hook note, subagent run,
    skill run or compaction); a turn end or a harness listing row opens no turn."""
    if record.event == "harness":
        entry = record.harness
        return entry is not None and is_note_kind(entry.kind) and entry.event is not None
    if record.event == "prompt_submit":
        return record.prompt is not None
    if record.event == "assistant_usage":
        return record.usage is not None
    if record.event == "subagent_run":
        return record.subagent_id is not None
    if record.event == "skill_run":
        return record.skill is not None
    return record.event in TURN_HELD_KINDS


def _gather_note(target: _Bucket, record: EventRecord, frame: Frame) -> None:
    entry = record.harness
    if entry is None or not is_note_kind(entry.kind) or entry.event is None:
        return
    note = XrayNote(entry.kind, entry.event, entry.label, frame.at(record) or 0.0, entry.chars // BYTES_PER_TOKEN)
    target.notes.append(note)


def _gather_bus(buckets: dict[int, _Bucket], bus: Sequence[EventRecord], ends: Sequence[float]) -> None:
    for record in bus:
        if record.subagent_id is not None:
            continue
        if record.event == "pre_tool" and record.tool is not None and record.tool.name == "Read":
            target = _bucket_of(buckets, record, ends)
            if target is not None and record.tool.path:
                target.reads.append(record.tool.path)


def build_turns(
    records: Sequence[EventRecord], bus: Sequence[EventRecord] | None, frame: Frame
) -> tuple[XrayTurn, ...]:
    """The main session's turns, the open last one included; `bus` is None when the bus holds no record."""
    replies = main_replies(records)
    ends = turn_end_times(records)
    skip = {id(record) for record in (*start_loads(records, replies), *start_notes(records, replies))}
    buckets: dict[int, _Bucket] = {}
    _gather_transcript(buckets, records, ends, skip, frame)
    _gather_bus(buckets, bus or [], ends)
    count = len(ends) + (1 if len(ends) in buckets else 0)
    turns: list[XrayTurn] = []
    for index in range(count):
        got = buckets.get(index, _Bucket())
        moment = ends[index] if index < len(ends) else got.last_time
        pre = got.compaction
        turns.append(
            XrayTurn(
                n=index + 1,
                t=moment - frame.t0,
                context_start=got.replies[0][1] if got.replies else None,
                context=got.replies[-1][1] if got.replies else None,
                loads=loads_of(got.loads, frame),
                reads=tuple(relative_wire_path(path, frame.root) for path in got.reads) if bus else None,
                subagents=tuple(got.runs),
                compaction=_compaction(pre, replies, frame.t0) if pre is not None else None,
                series=tuple(got.replies),
                prompts=tuple(got.prompts),
                notes=tuple(got.notes),
                skill_runs=tuple(got.skill_runs),
            )
        )
    return tuple(turns)


def build_subagents(records: Sequence[EventRecord], ends: Sequence[float], frame: Frame) -> tuple[XraySubagent, ...]:
    """One entry per subagent id the records name, in order of first appearance."""
    by_id: dict[str, list[EventRecord]] = {}
    for record in records:
        if record.subagent_id is not None:
            by_id.setdefault(record.subagent_id, []).append(record)
    return tuple(_subagent(sid, group, ends, frame) for sid, group in by_id.items())


def _subagent(sid: str, group: Sequence[EventRecord], ends: Sequence[float], frame: Frame) -> XraySubagent:
    run = next((record for record in group if record.event == "subagent_run"), None)
    times = sorted(moment for record in group if (moment := frame.at(record)) is not None)
    run_time = epoch(run.time) if run is not None else None
    series = sorted(
        (moment, context_of(record.usage))
        for record in group
        if record.event == "assistant_usage" and record.usage is not None and (moment := frame.at(record)) is not None
    )
    return XraySubagent(
        id=sid,
        type=run.subagent_type if run is not None else None,
        turn=None if run_time is None else turn_index(run_time, ends) + 1,
        start=times[0] if times else None,
        end=times[-1] if times else None,
        series=tuple(series),
        loads=loads_of(group, frame),
        skill_runs=tuple(
            _skill_run(record, frame) for record in group if record.event == "skill_run" and record.skill is not None
        ),
    )
