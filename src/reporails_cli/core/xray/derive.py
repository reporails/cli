"""The pieces of a node's own records: replies, compactions and what the harness put in at its start."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.platform.dto.events import (
    DELTA_KINDS,
    EventRecord,
    TokenUsage,
    is_note_kind,
)
from reporails_cli.core.platform.dto.xray import FindingTally, XrayHarnessItem, XrayWindow
from reporails_cli.core.platform.dto.xray_build import Frame, HarnessSlot, Replies
from reporails_cli.core.platform.dto.xray_graph import XrayCompaction

# How many bytes of file text one token stands for in a size estimate.
BYTES_PER_TOKEN = 4


def tokens_of(chars: int) -> int:
    """The tokens `chars` characters (or bytes) stand for in a size estimate."""
    return chars // BYTES_PER_TOKEN


# A context above this many tokens shows the session runs in the extended window of WINDOW_EXTENDED tokens.
WINDOW_STANDARD = 200_000
WINDOW_EXTENDED = 1_000_000


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


def count_for(findings: Mapping[str, FindingTally], path: str, root: Path) -> FindingTally | None:
    """The finding tally held for a file, by its absolute or project-relative path; None when none is held."""
    if path in findings:
        return findings[path]
    try:
        return findings.get(Path(path).relative_to(root).as_posix())
    except ValueError:
        return None


def frame_time(frame: Frame, record: EventRecord) -> float | None:
    """Seconds from the session's first transcript record to `record`, None for an unparsable time."""
    moment = epoch(record.time)
    return None if moment is None else moment - frame.t0


def file_tokens_est(path: str) -> int | None:
    """The file's size in tokens, estimated from its bytes; None when it is not a readable file."""
    try:
        target = Path(path)
        return tokens_of(target.stat().st_size) if target.is_file() else None
    except OSError:
        return None


def replies_of(records: Sequence[EventRecord]) -> Replies:
    """The `assistant_usage` records of `records` as (time, context), in time order."""
    points = [
        (moment, context_of(record.usage))
        for record in records
        if record.event == "assistant_usage" and record.usage is not None
        if (moment := epoch(record.time)) is not None
    ]
    return Replies(tuple(sorted(points)))


def latest_model(records: Sequence[EventRecord]) -> str | None:
    """The model of the main session's latest reply that names one."""
    models = [
        (moment, record.usage.model)
        for record in records
        if record.event == "assistant_usage"
        and record.subagent_id is None
        and record.usage is not None
        and record.usage.model is not None
        and (moment := epoch(record.time)) is not None
    ]
    return max(models)[1] if models else None


def window_of(replies: Replies) -> XrayWindow | None:
    """The extended window once a main reply's context exceeds the standard one; None before."""
    if any(context > WINDOW_STANDARD for _, context in replies.points):
        return XrayWindow(WINDOW_EXTENDED, "observed")
    return None


def build_compactions(records: Sequence[EventRecord], replies: Replies, frame: Frame) -> tuple[XrayCompaction, ...]:
    """Every compaction among `records` in time order, with the context before and after from `replies`."""
    found = sorted(
        (moment, record)
        for record in records
        if record.event == "post_compact"
        if (moment := epoch(record.time)) is not None
    )
    return tuple(
        XrayCompaction(
            t=moment - frame.t0,
            trigger="manual" if record.source == "manual" else "auto" if record.source == "auto" else None,
            before=replies.before(moment),
            after=replies.after(moment),
        )
        for moment, record in found
    )


def peak_context(replies: Replies, compactions: Sequence[XrayCompaction]) -> int | None:
    """The highest context the session reached: a main reply, or the context just before a compaction."""
    seen = [context for _, context in replies.points]
    seen.extend(compaction.before for compaction in compactions if compaction.before is not None)
    return max(seen, default=None)


def start_loads(records: Sequence[EventRecord], replies: Replies) -> list[EventRecord]:
    """The loads among `records` timed before the first of `replies`."""
    first = replies.points[0][0] if replies.points else float("inf")
    return [
        record
        for record in records
        if record.event == "instruction_load" and (moment := epoch(record.time)) is not None and moment < first
    ]


def start_notes(records: Sequence[EventRecord], replies: Replies) -> list[EventRecord]:
    """The session-start hook notes among `records` timed before the first of `replies`."""
    first = replies.points[0][0] if replies.points else float("inf")
    return [
        record
        for record in records
        if record.harness is not None
        and record.harness.kind == "hook_note"
        and record.harness.event == "SessionStart"
        and (moment := epoch(record.time)) is not None
        and moment < first
    ]


def build_harness(records: Sequence[EventRecord], replies: Replies) -> tuple[XrayHarnessItem, ...] | None:
    """The harness's own context in the main session: the first record of each kind, a list kind's delta rows
    summed up to the first compaction, and every session-start hook note timed before the first reply; None
    when the records hold no harness record."""
    started = {id(record) for record in start_notes(records, replies)}
    slots: list[HarnessSlot] = []
    by_kind: dict[str, HarnessSlot] = {}
    compacted = False
    for record in records:
        entry = record.harness
        if record.event == "post_compact":
            compacted = True
        elif record.event != "harness" or entry is None:
            continue
        elif is_note_kind(entry.kind):
            if id(record) in started:
                slots.append(HarnessSlot.of(entry))
        elif entry.kind not in by_kind:
            by_kind[entry.kind] = HarnessSlot.of(entry)
            slots.append(by_kind[entry.kind])
        elif entry.kind in DELTA_KINDS and not compacted:
            by_kind[entry.kind].add(entry)
    items = [XrayHarnessItem(slot.kind, slot.label, slot.count, tokens_of(slot.chars)) for slot in slots]
    return tuple(items) if items else None
