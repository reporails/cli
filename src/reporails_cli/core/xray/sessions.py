"""Which session of a project the x-ray shows, and the facts the session switcher lists for each."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.eventbus.port import get_transcript_adapter
from reporails_cli.core.eventbus.transcript import (
    known_session,
    last_write,
    newest_session,
    recent_sessions,
    session_anywhere,
    session_cwd,
    session_start,
    subagent_count,
)
from reporails_cli.core.pipeline.expected_loads import AGENT
from reporails_cli.core.platform.config.bootstrap import env_text
from reporails_cli.core.platform.dto.xray import PickedSession, XraySessionEntry
from reporails_cli.core.xray.derive import epoch


def _calling_id() -> str:
    """The id of the session the calling agent's own env var names; empty when it names none."""
    adapter = get_transcript_adapter(AGENT)
    return env_text(adapter.session_env) if adapter is not None else ""


def _recorded_root(transcript: Path, fallback: Path) -> Path:
    """The folder the transcript records the agent ran in, else `fallback`."""
    recorded = session_cwd(AGENT, transcript)
    return fallback if recorded is None else Path(recorded)


def pick_session(root: Path, named: str | None, *, current: bool) -> PickedSession | None:
    """The session to show, the project folder it belongs to and how it was chosen.

    Reads only the sessions recorded for `root`, the folder the command runs in. A named session must be one of
    them, else None. `current` takes the session the calling agent's env var names, found in any of the agent's
    project folders, its folder the one the transcript records; when no transcript has that id it takes the
    newest session of `root`, picked as `current_unknown`. With neither, the newest. None when `root` has none."""
    if named is not None:
        transcript = known_session(root, named)
        return None if transcript is None else PickedSession(root, transcript, "named")
    calling = _calling_id() if current else ""
    mine = session_anywhere(calling) if calling else None
    if mine is not None:
        return PickedSession(_recorded_root(mine, root), mine, "current")
    newest = newest_session(root)
    if newest is None:
        return None
    return PickedSession(root, newest, "current_unknown" if current else "newest")


def _entry(session_file: Path) -> XraySessionEntry:
    started_at = session_start(AGENT, session_file)
    began = None if started_at is None else epoch(started_at)
    written = last_write(session_file)
    length = None if began is None or written is None else max(0.0, written - began)
    return XraySessionEntry(session_file.stem, started_at, length, subagent_count(session_file))


def session_entries(root: Path) -> tuple[XraySessionEntry, ...]:
    """The facts of each recent session of the project, the most recently written first."""
    return tuple(_entry(path) for path in recent_sessions(root))
