"""The line `ails xray` prints for the page it shows."""

from __future__ import annotations

from reporails_cli.core.platform.dto.xray import SessionPick

_UNKNOWN_NOTE = "  (the newest session of this folder: the agent did not say which session it is)"


def xray_line(session_id: str, url: str, picked: SessionPick) -> str:
    """`x-ray of session <id>: <url>`, with a note when the session shown is only the newest one."""
    note = _UNKNOWN_NOTE if picked == "current_unknown" else ""
    return f"x-ray of session {session_id}: {url}{note}"
