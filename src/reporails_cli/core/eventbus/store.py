"""The session-log folder: the one owner of its files, modes and pruning."""

from __future__ import annotations

import contextlib
import json
import os
import re
import time
from pathlib import Path

from reporails_cli.core.platform.config.bootstrap import get_xray_log_dir
from reporails_cli.core.platform.dto.events import EventRecord

LOG_RETENTION_DAYS = 30
LOG_FOLDER_MAX_BYTES = 100 * 1024 * 1024
# `<session id>.<start ms>.<part>.jsonl` (the x-ray mod's log) or `<session id>.events.jsonl`.
_LOG_NAME = re.compile(r"^[^.]+\.(\d+\.\d+|events)\.jsonl$")
_UNSAFE = re.compile(r"[^A-Za-z0-9_-]")


def events_path(session_id: str) -> Path:
    """The event-log file of one session."""
    return get_xray_log_dir() / f"{_UNSAFE.sub('', session_id) or 'unknown'}.events.jsonl"


def append(record: EventRecord) -> None:
    """Append one line to the session's event log (folder 0700, file 0600). Raises `OSError`."""
    get_xray_log_dir().mkdir(mode=0o700, parents=True, exist_ok=True)
    line = (json.dumps(record.to_json()) + "\n").encode()
    fd = os.open(events_path(record.session_id), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def prune(root: Path | None) -> None:
    """Keep the event-log folder private and small: mode 0700 folder, 0600 logs, whole
    sessions removed after 30 days (sooner under Claude Code's `cleanupPeriodDays`), then oldest
    sessions until the folder is under 100 MB. Best-effort: a folder or file that cannot be
    read or changed is left alone and never changes the answer."""
    # pylint: disable-next=import-outside-toplevel  # the per-event path stays light
    from reporails_cli.core.cache.sweep import sweep

    # pylint: disable-next=import-outside-toplevel  # the per-event path stays light
    from reporails_cli.core.platform.config.claude_settings import claude_cleanup_period_days

    # Best-effort housekeeping: an OSError here must not fail the command.
    with contextlib.suppress(OSError):
        folder = get_xray_log_dir()
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        folder.chmod(0o700)
        logs = [p for p in folder.iterdir() if _LOG_NAME.match(p.name)]
        for log in logs:
            with contextlib.suppress(OSError):
                log.chmod(0o600)
        days = min(LOG_RETENTION_DAYS, claude_cleanup_period_days(root) or LOG_RETENTION_DAYS)
        sweep(
            logs,
            unit_of=lambda p: p.name.split(".", 1)[0],
            now=time.time(),
            max_age_s=days * 86400,
            max_bytes=LOG_FOLDER_MAX_BYTES,
        )
