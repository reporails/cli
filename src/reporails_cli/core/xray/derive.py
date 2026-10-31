"""Turn one session's event records into loads, turns and subagent runs."""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.dto.events import EventRecord, TokenUsage
from reporails_cli.core.platform.dto.xray import (
    LOAD_KIND_OF_MEMORY_TYPE,
    CompactionTrigger,
    XrayCompaction,
    XrayHarnessItem,
    XrayLoad,
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
    """What a derivation reads beside the records: the session's first time, the project and its findings."""

    t0: float
    root: Path
    findings: Mapping[str, int]

    def at(self, record: EventRecord) -> float | None:
        """Seconds from the session's first transcript record to `record`, None for an unparsable time."""
        moment = epoch(record.time)
        return None if moment is None else moment - self.t0


def _tokens_est(path: str) -> int | None:
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
            tokens_est=_tokens_est(record.load.path),
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


def _compaction(pre: EventRecord, bus: Sequence[EventRecord], replies: Replies, t0: float) -> XrayCompaction | None:
    moment = epoch(pre.time)
    if moment is None:
        return None
    after_at = next(
        (
            when
            for record in bus
            if record.event == "post_compact" and (when := epoch(record.time)) is not None and when >= moment
        ),
        None,
    )
    trigger: CompactionTrigger | None = "manual" if pre.source == "manual" else "auto" if pre.source == "auto" else None
    return XrayCompaction(
        t=moment - t0,
        trigger=trigger,
        before=replies.before(moment),
        after=None if after_at is None else replies.after(after_at),
    )


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


def build_harness(records: Sequence[EventRecord], replies: Replies, frame: Frame) -> tuple[XrayHarnessItem, ...] | None:
    """The harness's own context in the main session: the first record of each kind and every session-start hook
    note timed before the first reply; None when the records hold no harness record."""
    first = replies.points[0][0] if replies.points else float("inf")
    seen: set[str] = set()
    items: list[XrayHarnessItem] = []
    for record in records:
        entry = record.harness
        if record.event != "harness" or entry is None or record.subagent_id is not None:
            continue
        if entry.kind == "hook_note":
            moment = epoch(record.time)
            if moment is None or moment >= first:
                continue
        elif entry.kind in seen:
            continue
        seen.add(entry.kind)
        items.append(
            XrayHarnessItem(entry.kind, entry.label, entry.count, entry.chars // BYTES_PER_TOKEN, frame.at(record))
        )
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
        if id(record) in skip or record.event == "harness":
            continue
        if record.subagent_id is not None and record.event != "subagent_run":
            continue
        target = _bucket_of(buckets, record, ends)
        if target is None:
            continue
        if record.event == "assistant_usage" and record.usage is not None:
            target.replies.append((frame.at(record) or 0.0, context_of(record.usage)))
        elif record.event == "instruction_load":
            target.loads.append(record)
        elif record.event == "subagent_run" and record.subagent_id is not None:
            target.runs.append(record.subagent_id)


def _gather_bus(buckets: dict[int, _Bucket], bus: Sequence[EventRecord], ends: Sequence[float]) -> None:
    for record in bus:
        if record.subagent_id is not None:
            continue
        if record.event == "pre_tool" and record.tool is not None and record.tool.name == "Read":
            target = _bucket_of(buckets, record, ends)
            if target is not None and record.tool.path:
                target.reads.append(record.tool.path)
        elif record.event == "pre_compact":
            target = _bucket_of(buckets, record, ends)
            if target is not None and target.compaction is None:
                target.compaction = record


def build_turns(
    records: Sequence[EventRecord], bus: Sequence[EventRecord] | None, frame: Frame
) -> tuple[XrayTurn, ...]:
    """The main session's turns, the open last one included; `bus` is None when the bus holds no record."""
    replies = main_replies(records)
    ends = turn_end_times(records)
    skip = {id(record) for record in start_loads(records, replies)}
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
                replies=len(got.replies),
                loads=loads_of(got.loads, frame),
                reads=tuple(relative_wire_path(path, frame.root) for path in got.reads) if bus else None,
                subagents=tuple(got.runs),
                compaction=_compaction(pre, bus or [], replies, frame.t0) if pre is not None else None,
                series=tuple(got.replies),
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
    )
