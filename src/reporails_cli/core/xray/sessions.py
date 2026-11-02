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
from reporails_cli.core.platform.dto.xray import SessionPick, XraySessionEntry
from reporails_cli.core.xray.derive import epoch


def _calling_session(root: Path) -> Path | None:
    """The transcript of the session the agent's own env var names, when it is a session of the project."""
    adapter = get_transcript_adapter(AGENT)
    session_id = env_text(adapter.session_env) if adapter is not None else ""
    return known_session(root, session_id) if session_id else None


def pick_session(root: Path, named: str | None, *, current: bool) -> tuple[Path, SessionPick] | None:
    """The transcript to show and how it was chosen.

    A named session must be one of the project's, else None. `current` takes the session the calling agent's
    env var names, else the newest one, picked as `current_unknown`. With neither, the newest. None when the
    project has no session."""
    if named is not None:
        path = known_session(root, named)
        return None if path is None else (path, "named")
    if current:
        calling = _calling_session(root)
        if calling is not None:
            return calling, "current"
    newest = newest_session(root)
    if newest is None:
        return None
    return newest, "current_unknown" if current else "newest"


def _entry(session_file: Path) -> XraySessionEntry:
    started_at = session_start(AGENT, session_file)
    began = None if started_at is None else epoch(started_at)
    written = last_write(session_file)
    length = None if began is None or written is None else max(0.0, written - began)
    return XraySessionEntry(session_file.stem, started_at, length, subagent_count(session_file))


def session_entries(root: Path) -> tuple[XraySessionEntry, ...]:
    """The facts of each recent session of the project, the most recently written first."""
    return tuple(_entry(path) for path in recent_sessions(root))
