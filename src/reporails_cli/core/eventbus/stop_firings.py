"""Which Stop hook firings of a transcript row are one handler's report."""

from __future__ import annotations

from reporails_cli.core.platform.dto.events import EventRecord


def one_stop_firing_per_handler(
    resolved: list[EventRecord], blocked: tuple[str | None, ...]
) -> tuple[list[EventRecord], tuple[str | None, ...]]:
    """The records of one row without the stop summary entry of a handler a blocking row already reported, and the
    blocked handlers still waiting for their summary. A stop summary row, whose entries carry no row id and no exit
    code, settles every waiting handler."""
    stop = [r.hook for r in resolved if r.event == "hook_firing" and r.hook is not None and r.hook.event == "Stop"]
    waiting = (*blocked, *(f.command for f in stop if f.decision == "blocked" and f.command is not None))
    summary = [f for f in stop if f.decision == "ran" and f.id is None and f.exit_code is None]
    if not summary:
        return resolved, waiting
    pending = list(blocked)
    kept: list[EventRecord] = []
    for record in resolved:
        if record.hook in summary and record.hook is not None and record.hook.command in pending:
            pending.remove(record.hook.command)
            continue
        kept.append(record)
    return kept, ()
