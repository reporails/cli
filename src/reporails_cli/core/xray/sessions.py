"""Which session of a project the x-ray shows, and the facts the session switcher lists for each."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.eventbus.port import get_transcript_adapter
from reporails_cli.core.eventbus.transcript import (
    known_session,
    last_write,
    newest_session,
    recent_sessions,
    session_start,
    subagent_count,
)
from reporails_cli.core.pipeline.expected_loads import AGENT
from reporails_cli.core.platform.config.bootstrap import env_text
from reporails_cli.core.platform.dto.xray import PickedSession, SessionPick, XraySessionEntry
from reporails_cli.core.xray.derive import epoch


def _calling_id() -> str:
    """The id of the session the calling agent's own env var names; empty when it names none."""
    adapter = get_transcript_adapter(AGENT)
    return env_text(adapter.session_env) if adapter is not None else ""


def _holding(folders: tuple[Path, ...], session_id: str, picked: SessionPick) -> PickedSession | None:
    """The nearest of `folders` that holds session `session_id`, picked as `picked`; None when none does."""
    for folder in folders:
        transcript = known_session(folder, session_id)
        if transcript is not None:
            return PickedSession(folder, transcript, picked)
    return None


def pick_session(start: Path, named: str | None, *, current: bool) -> PickedSession | None:
    """The session to show, the folder Claude Code holds it under and how it was chosen.

    The folder is `start` or the nearest folder above it with a session, so a command run in a subfolder of the
    folder Claude Code was started in finds its sessions. A named session must be held by one of them, else None.
    `current` takes the session the calling agent's env var names, else the newest one, picked as
    `current_unknown`. With neither, the newest. None when no such folder has a session."""
    folders = (start, *start.parents)
    if named is not None:
        return _holding(folders, named, "named")
    calling = _calling_id() if current else ""
    if calling:
        mine = _holding(folders, calling, "current")
        if mine is not None:
            return mine
    for folder in folders:
        newest = newest_session(folder)
        if newest is not None:
            return PickedSession(folder, newest, "current_unknown" if current else "newest")
    return None


def _entry(session_file: Path) -> XraySessionEntry:
    started_at = session_start(AGENT, session_file)
    began = None if started_at is None else epoch(started_at)
    written = last_write(session_file)
    length = None if began is None or written is None else max(0.0, written - began)
    return XraySessionEntry(session_file.stem, started_at, length, subagent_count(session_file))


def session_entries(root: Path) -> tuple[XraySessionEntry, ...]:
    """The facts of each recent session of the project, the most recently written first."""
    return tuple(_entry(path) for path in recent_sessions(root))
