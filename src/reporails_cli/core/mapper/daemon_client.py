"""Daemon client — talks to the global mapper daemon over Unix socket.

Falls back gracefully: if daemon is not running or unreachable,
returns None and caller uses in-process mapping.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from enum import Enum
from pathlib import Path

from packaging.version import InvalidVersion, Version

from reporails_cli.core.mapper.daemon import (
    code_identity,
    daemon_pid,
    is_daemon_running,
    retire_daemon,
    socket_path,
    start_daemon,
)
from reporails_cli.core.mapper.serialize import ruleset_map_from_json
from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from reporails_cli.core.platform.contract.http_get import HttpGet
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object
from reporails_cli.core.platform.dto.ports import DaemonTransport
from reporails_cli.core.platform.dto.ruleset import RulesetMap

logger = logging.getLogger(__name__)


class DaemonStatus(str, Enum):
    """Result of ``ensure_daemon`` — drives caller's user-visible messaging."""

    ATTACHED = "attached"  # daemon already running, ping succeeded
    STARTED = "started"  # we forked it; ping confirms it is responding
    STARTING = "starting"  # we forked it; socket exists but ping not yet ack'd
    UNAVAILABLE = "unavailable"  # Windows, fork failure, or process died


def ping(transport: DaemonTransport) -> JsonObject | None:
    """Ping daemon. Returns response dict or None if unreachable."""
    try:
        return transport.exchange(socket_path(), {"cmd": "ping"}, timeout=5.0, on_message=None)
    except PlatformUnavailableError:
        return None


def _code_key(code: str) -> tuple[Version, int] | None:
    """`(package version, map version)` of a code identity, or None when it does not parse."""
    package, sep, mapper = code.rpartition("+map")
    try:
        return (Version(package), int(mapper)) if sep else None
    except (InvalidVersion, ValueError):
        return None


def runs_older_code(pong: JsonObject) -> bool:
    """Whether a daemon reply comes from an older version than this process: one from before
    the reply carried its code, or one whose package or map version is lower."""
    code = pong.get("code")
    if not isinstance(code, str):
        return True
    theirs, ours = _code_key(code), _code_key(code_identity())
    return theirs is not None and ours is not None and theirs < ours


def runs_newer_code(pong: JsonObject) -> bool:
    """Whether a daemon reply comes from a newer version than this process."""
    code = pong.get("code")
    theirs = _code_key(code) if isinstance(code, str) else None
    ours = _code_key(code_identity())
    return theirs is not None and ours is not None and theirs > ours


def serves_this_code(pong: JsonObject | None) -> bool:
    """Whether a daemon reply (a ping or a map) comes from a daemon that maps with this
    process's code.

    Another installed version's daemon (or one from before the reply carried its code) maps
    with its own mapper, so its map is not this version's.
    """
    return pong is not None and pong.get("code") == code_identity()


def _forward_progress(progress: Callable[[str], None] | None) -> Callable[[JsonObject], None] | None:
    """A frame handler handing each streamed progress message to `progress`, or None when nobody listens."""
    if progress is None:
        return None

    def forward(frame: JsonObject) -> None:
        # A spinner/render error in the caller's callback must never abort the map or the result read.
        try:
            progress(str(frame.get("msg", "")))
        except Exception:  # pylint: disable=broad-exception-caught  # caller callback must never abort the map
            logger.debug("map progress callback raised; ignoring", exc_info=True)

    return forward


def map_ruleset_via_daemon(
    transport: DaemonTransport,
    paths: list[Path],
    root: Path,
    segmentation: str,
    progress: Callable[[str], None] | None = None,
) -> RulesetMap | None:
    """Map ruleset via global daemon, with the requested `segmentation`. Returns RulesetMap or None on failure.

    Caller should fall back to in-process mapping when this returns None.

    The daemon streams JSON lines: zero or more ``{"type": "progress", "msg": ...}``
    lines (forwarded to ``progress`` so the caller's spinner advances per harness
    element on the daemon path too, not just in-process), followed by the single
    result line carrying ``ok`` + ``ruleset_map``. A malformed line or a closed
    stream before the result yields None so the caller falls back to in-process.
    """
    request: JsonObject = {
        "cmd": "map_ruleset",
        "paths": [str(p) for p in paths],
        "root": str(root),
        "segmentation": segmentation,
    }
    # Matches the daemon-side connection timeout; covers a cold model load and the
    # first encode, plus mapping work, with headroom.
    try:
        response = transport.exchange(socket_path(), request, timeout=300.0, on_message=_forward_progress(progress))
    except PlatformUnavailableError:
        logger.debug("Daemon map_ruleset failed: no response")
        return None
    if not response.get("ok"):
        logger.debug("Daemon map_ruleset failed: %s", response.get("error"))
        return None
    if not serves_this_code(response):
        # Mapped by another version's code: not this version's map.
        logger.debug("Daemon map_ruleset came from other code: %s", response.get("code"))
        return None

    # Deserialize the RulesetMap from JSON
    map_data = response.get("ruleset_map")
    if map_data is None:
        return None

    try:
        return ruleset_map_from_json(as_object(map_data))
    except (RuntimeError, ValueError):
        logger.debug("Failed to deserialize daemon response", exc_info=True)
        return None


def _reconcile_running_daemon(transport: DaemonTransport) -> DaemonStatus | None:
    """Status decided by an already-running daemon, or None when this version must start its own."""
    if not is_daemon_running():
        return None
    # One busy mapping misses the ping; it is attached as before, and a map it returns from
    # other code is refused on arrival. A daemon that answers with other code is never used:
    # an older version's (left over from before an upgrade) is replaced by this version's
    # once it has exited, a newer version's is left to that version.
    pong = ping(transport)
    if pong is None or serves_this_code(pong):
        return DaemonStatus.ATTACHED
    if not runs_older_code(pong):
        return DaemonStatus.UNAVAILABLE
    # Not retired because it is busy or slow to exit: leave it. Not retired because it is
    # already gone or replaced (a check running beside this one got there first): start or
    # attach to this version's below.
    if not retire_daemon(transport, pong.get("pid")) and daemon_pid() == pong.get("pid"):
        return DaemonStatus.UNAVAILABLE
    return None


def ensure_daemon(
    transport: DaemonTransport, fetch: HttpGet, emit: Callable[[str], None] | None = None
) -> DaemonStatus:
    """Ensure global daemon is running. Start it if not.

    Returns a status enum the caller uses to drive user-visible messaging and
    decide whether to attempt a daemon round-trip or go straight to in-process
    mapping. A readiness ping after ``start_daemon`` distinguishes a fully
    attached daemon (``STARTED``) from one whose socket is bound but whose
    model warmup is still in flight (``STARTING``).

    When ``emit`` is given, reports the cold-start sub-phases (``Starting
    Reporails...`` → ``Loading tools...``) so a caller's spinner shows the start
    sequence; an already-running daemon (``ATTACHED``) emits nothing.
    """
    say = emit if emit is not None else (lambda _msg: None)

    status = _reconcile_running_daemon(transport)
    if status is not None:
        return status

    say("Starting Reporails...")
    try:
        start_daemon(transport, fetch)
    except OSError:
        return DaemonStatus.UNAVAILABLE

    if not is_daemon_running():
        return DaemonStatus.UNAVAILABLE

    say("Loading tools...")
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if ping(transport) is not None:
            return DaemonStatus.STARTED
        time.sleep(0.05)
    return DaemonStatus.STARTING
