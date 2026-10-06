"""Which notices are due on this run: a warning always, an info once per local day.

The ids already shown are kept in `~/.reporails/notices-seen.json` as `{id: "YYYY-MM-DD"}`,
and entries older than 30 days are dropped. Every failure here (unreadable, corrupt or
unwritable file) degrades to "show the notice" — the worst case is a repeated line, never
a lost one.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta
from pathlib import Path

from reporails_cli.core.platform.dto.diagnostics import Notice
from reporails_cli.core.platform.utils.utils import write_json_atomic

logger = logging.getLogger(__name__)

KEEP_DAYS = 30


def _seen_path() -> Path:
    """The state file, resolved from the home directory at call time."""
    return Path.home() / ".reporails" / "notices-seen.json"


def _load() -> dict[str, str]:
    """The stored `{id: day}` entries; empty when the file is absent, unreadable or not an object."""
    data: object = {}
    try:
        data = json.loads(_seen_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.debug("No notices-seen file yet")
    except (OSError, ValueError) as exc:
        logger.debug("Ignoring unreadable notices-seen file: %s", exc)
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


def _recent(day: str, cutoff: date) -> bool:
    """True when `day` is an ISO date on or after `cutoff`."""
    parsed: date | None = None
    try:
        parsed = date.fromisoformat(day)
    except ValueError:
        logger.debug("Dropping notices-seen entry with an unreadable day: %r", day)
    return parsed is not None and parsed >= cutoff


def _save(entries: dict[str, str]) -> None:
    try:
        write_json_atomic(_seen_path(), entries)
    except OSError as exc:
        logger.debug("Could not persist notices-seen: %s", exc)


def due_notices(notices: tuple[Notice, ...], *, now: datetime | None = None) -> tuple[Notice, ...]:
    """The notices to show now; the info ones returned are recorded as shown today."""
    if not notices:
        return ()
    today = (now or datetime.now()).astimezone().date()
    stored = _load()
    entries = {k: v for k, v in stored.items() if _recent(v, today - timedelta(days=KEEP_DAYS))}
    due = tuple(n for n in notices if n.level == "warn" or entries.get(n.id) != today.isoformat())
    for notice in due:
        if notice.level != "warn":
            entries[notice.id] = today.isoformat()
    if entries != stored:
        _save(entries)
    return due
