"""Read a session's event log."""

from __future__ import annotations

import contextlib
import json

from reporails_cli.core.eventbus.store import events_path
from reporails_cli.core.platform.contract.json_value import as_object
from reporails_cli.core.platform.dto.events import EventRecord


def read_events(session_id: str, after: int) -> tuple[list[EventRecord], int]:
    """The records after the first `after` ones, in file order, and the offset to pass next time.

    A torn last line (no newline yet) is left for the next read; an unreadable line is skipped."""
    try:
        data = events_path(session_id).read_bytes()
    except OSError:
        return [], after
    records: list[EventRecord] = []
    for line in data.split(b"\n")[:-1]:
        with contextlib.suppress(ValueError):
            records.append(EventRecord.from_json(as_object(json.loads(line))))
    return records[after:], max(after, len(records))
