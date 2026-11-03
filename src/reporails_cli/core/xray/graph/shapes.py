"""What each agent type was launched with, read from the first request each subagent's file records."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence

from reporails_cli.core.platform.dto.events import EventRecord, RequestSize
from reporails_cli.core.xray.derive import tokens_of


def first_requests(records: Sequence[EventRecord]) -> dict[str, RequestSize]:
    """The first request each subagent's file records, by subagent id."""
    first: dict[str, RequestSize] = {}
    for record in records:
        if record.subagent_id is not None and record.request is not None:
            first.setdefault(record.subagent_id, record.request)
    return first


def launched_with(
    launch_ids: Iterable[str], first: dict[str, RequestSize]
) -> tuple[int | None, tuple[tuple[str, int], ...]]:
    """The system prompt size in tokens of the first launch (lowest id) that recorded a request, and each tool the
    launches were sent with and how many launches had it, most launches first then by name; None and no tools when
    no launch recorded one."""
    sizes = [first[node_id] for node_id in sorted(launch_ids) if node_id in first]
    if not sizes:
        return None, ()
    counts = Counter(name for size in sizes for name in set(size.tool_names))
    return tokens_of(sizes[0].system_chars), tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0])))
