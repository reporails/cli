"""Which session of a project the x-ray shows, and the facts the session switcher lists for each."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.eventbus.port import get_transcript_adapter
from reporails_cli.core.eventbus.transcript import (
    first_row_time,
    known_session,
    last_write,
    newest_session,
    opens_with_clear,
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

# The span around the first row of a transcript a `/clear` opened in which the last write of the session it
# replaces falls: the agent writes the session it leaves until just after the new one begins.
_REPLACED_BEFORE_S = 5.0
_REPLACED_AFTER_S = 1.0


def _calling_id() -> str:
    """The id of the session the calling agent's own env var names; empty when it names none."""
    adapter = get_transcript_adapter(AGENT)
    return env_text(adapter.session_env) if adapter is not None else ""


def _recorded_root(transcript: Path, fallback: Path) -> Path:
    """The folder the transcript records the agent ran in, else `fallback`."""
    recorded = session_cwd(AGENT, transcript)
    return fallback if recorded is None else Path(recorded)


def _cleared_starts(root: Path, mine: Path) -> dict[Path, float]:
    """The time of the first row of each recent transcript of `root` other than `mine` that opens with `/clear`, in
    seconds since 1970."""
    starts: dict[Path, float] = {}
    for path in recent_sessions(root):
        started_at = None if path == mine else first_row_time(AGENT, path)
        began = None if started_at is None else epoch(started_at)
        if began is not None and opens_with_clear(AGENT, path):
            starts[path] = began
    return starts


def _replacing(session: Path, cleared: dict[Path, float]) -> list[Path]:
    """The transcripts of `cleared` that replace `session`: the last write to `session` falls between
    `_REPLACED_BEFORE_S` before and `_REPLACED_AFTER_S` after their first row."""
    left_at = last_write(session)
    if left_at is None:
        return []
    return [path for path, began in cleared.items() if -_REPLACED_BEFORE_S <= left_at - began <= _REPLACED_AFTER_S]


def _in_use(folder: Path, mine: Path) -> PickedSession:
    """The session in use of the one the calling agent started with, following each `/clear` that replaced it;
    the newest of `folder`, picked as `current_unknown`, when more than one transcript replaces a session."""
    cleared = _cleared_starts(folder, mine)
    session = mine
    while replacing := _replacing(session, cleared):
        if len(replacing) > 1:
            return PickedSession(folder, newest_session(folder) or session, "current_unknown")
        session = replacing[0]
        del cleared[session]
    return PickedSession(folder, session, "current")


def pick_session(root: Path, named: str | None, *, current: bool) -> PickedSession | None:
    """The session to show, the project folder it belongs to and how it was chosen.

    Reads only the sessions recorded for `root`, the folder the command runs in. A named session must be one of
    them, else None. `current` takes the session the calling agent's env var names, found in any of the agent's
    project folders, its folder the one the transcript records. The agent keeps the id it started with across
    `/clear`: a transcript of that folder that opens with a `/clear` command replaces a session whose last write
    falls between `_REPLACED_BEFORE_S` before and `_REPLACED_AFTER_S` after its first row, so a session written on
    after another terminal's `/clear` is not replaced. Each replacement is followed to the session no transcript
    replaces; when more than one replaces a session, the newest of the folder is taken, picked as
    `current_unknown`. When no transcript has the id it takes the newest session of `root`, picked as
    `current_unknown`. With neither, the newest. None when `root` has none."""
    if named is not None:
        transcript = known_session(root, named)
        return None if transcript is None else PickedSession(root, transcript, "named")
    calling = _calling_id() if current else ""
    mine = session_anywhere(calling) if calling else None
    if mine is not None:
        return _in_use(_recorded_root(mine, root), mine)
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
