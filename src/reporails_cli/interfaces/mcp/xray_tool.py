"""The `xray` tool's body: start the project's session x-ray page in the background and answer its address."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.platform.contract.errors import XrayPageError
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.xray.pages import page_url, start_page
from reporails_cli.core.xray.sessions import pick_session


def xray_page(path: str, session: str) -> JsonObject:
    """The address of the session's x-ray page for the project at `path`, started in the background or reused.

    With no `session`, the session of the calling agent, else the newest one. Answers `no_session` when the
    project has none (or `session` is not one of them) and `page_not_started` when the page does not come up."""
    root = Path(path).resolve()
    chosen = pick_session(root, session or None, current=not session)
    if chosen is None:
        return {
            "error": "no_session",
            "message": f"No session {session} in {root}." if session else f"No Claude Code session found for {root}.",
        }
    transcript, picked = chosen
    try:
        page, reused = start_page(root, transcript.stem)
    except XrayPageError as err:
        return {"error": "page_not_started", "message": str(err)}
    return {
        "url": page_url(page, transcript.stem, picked),
        "session": transcript.stem,
        "picked": picked,
        "reused": reused,
    }
