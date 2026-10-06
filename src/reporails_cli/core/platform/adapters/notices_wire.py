"""Notices as the client reads them off the wire.

Two carriers: the `X-Reporails-Notices` response header (base64url of a UTF-8 JSON array)
and a `notices` list in a JSON body. A malformed entry is dropped with a warning; a header
that cannot be decoded drops every notice from it. Neither stops the run.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from reporails_cli.core.platform.dto.diagnostics import NOTICE_LEVELS, Notice

logger = logging.getLogger(__name__)

NOTICES_HEADER = "X-Reporails-Notices"

# More than this many notices in one reply is not read: the rest are dropped.
MAX_NOTICES = 10


def _notice(entry: Any) -> Notice | None:
    """One entry as a `Notice`; `None` when it is not a dict with a usable id, level, text and url."""
    if not isinstance(entry, dict):
        return None
    ident, level, text = entry.get("id"), entry.get("level"), entry.get("text")
    url = entry.get("url", "")
    if not (isinstance(ident, str) and ident and isinstance(text, str) and text):
        return None
    if not (isinstance(level, str) and isinstance(url, str)) or level not in NOTICE_LEVELS:
        return None
    return Notice(id=ident, level=level, text=text, url=url)


def notices_from_list(raw: object) -> tuple[Notice, ...]:
    """The well-formed notices in `raw`, first of each id, at most `MAX_NOTICES`.

    Anything that is not a list gives no notices. Each dropped entry is named in a warning.
    """
    if not isinstance(raw, list):
        if raw is not None:
            logger.warning("Ignoring notices: expected a list, got %s", type(raw).__name__)
        return ()
    kept: dict[str, Notice] = {}
    for index, entry in enumerate(raw):
        notice = _notice(entry)
        if notice is None:
            logger.warning("Dropping malformed notice at position %d", index)
        elif notice.id in kept:
            logger.warning("Dropping repeated notice id %r", notice.id)
        else:
            kept[notice.id] = notice
    if len(kept) > MAX_NOTICES:
        logger.warning("Dropping %d notices beyond the first %d", len(kept) - MAX_NOTICES, MAX_NOTICES)
    return tuple(kept.values())[:MAX_NOTICES]


def notices_from_header(value: str | None) -> tuple[Notice, ...]:
    """The notices a header value carries; none when absent, undecodable or not a list."""
    if not value:
        return ()
    decoded: object = None
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except ValueError as exc:
        logger.warning("Ignoring the notices header: it could not be decoded (%s)", exc)
    return notices_from_list(decoded)
