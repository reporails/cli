"""Read a session's event log."""

from __future__ import annotations

import contextlib
import json

from reporails_cli.core.eventbus.store import events_path
from reporails_cli.core.eventbus.tail import read_appended_lines
from reporails_cli.core.platform.contract.json_value import as_object
from reporails_cli.core.platform.dto.events import EventRecord


def read_events(session_id: str, after: int) -> tuple[list[EventRecord], int]:
    """The records appended after byte offset `after`, in file order, and the offset to pass next time.

    A torn last line (no newline yet) is left for the next read; an unreadable line is skipped."""
    lines, next_offset = read_appended_lines(events_path(session_id), after)
    records: list[EventRecord] = []
    for line in lines:
        with contextlib.suppress(ValueError):
            records.append(EventRecord.from_json(as_object(json.loads(line))))
    return records, next_offset
