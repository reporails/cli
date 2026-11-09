"""The `xray` tool's body: start the project's session x-ray page in the background and answer its address."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.platform.contract.errors import XrayPageError
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.xray.pages import page_url, start_page
from reporails_cli.core.xray.sessions import pick_session


def xray_page(path: str, session: str) -> JsonObject:
    """The address of the session's x-ray page for the project at `path`, started in the background or reused.

    With no `session`, the session of the calling agent, else the newest one. After `/clear` the calling agent's
    session is the one the `/clear` opened, followed through each later `/clear`; a session another terminal
    opens with `/clear` while the calling agent goes on writing its own is not taken. When two sessions opened
    with `/clear` as one session ended, the newest of those two and `picked` is `current_ambiguous`.
    Answers `no_session` when the project has none (or `session` is not one of them) and `page_not_started`
    when the page does not come up."""
    here = Path(path).resolve()
    chosen = pick_session(here, session or None, current=not session)
    if chosen is None:
        missing = f"No session {session}" if session else "No Claude Code session found"
        return {
            "error": "no_session",
            "message": f"{missing} for {here}; run it in the folder Claude Code was started in.",
        }
    session_id = chosen.transcript.stem
    try:
        page, reused = start_page(chosen.root, session_id)
    except XrayPageError as err:
        return {"error": "page_not_started", "message": str(err)}
    return {
        "url": page_url(page, session_id, chosen.picked),
        "session": session_id,
        "picked": chosen.picked,
        "reused": reused,
    }
