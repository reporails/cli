"""Daemon client — talks to the global mapper daemon over Unix socket.

Falls back gracefully: if daemon is not running or unreachable,
returns None and caller uses in-process mapping.
"""

from __future__ import annotations

import json
import logging
import socket
import sys
import time
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class DaemonStatus(str, Enum):
    """Result of ``ensure_daemon`` — drives caller's user-visible messaging."""

    ATTACHED = "attached"  # daemon already running, ping succeeded
    STARTED = "started"  # we forked it; ping confirms it is responding
    STARTING = "starting"  # we forked it; socket exists but ping not yet ack'd
    UNAVAILABLE = "unavailable"  # Windows, fork failure, or process died


def _socket_path() -> Path:
    from reporails_cli.core.platform.config.bootstrap import get_daemon_dir

    return get_daemon_dir() / "mapper.sock"


def connect(timeout: float = 5.0) -> socket.socket | None:
    """Connect to global daemon socket. Returns None if unreachable."""
    if sys.platform == "win32":
        return None
    sock_path = _socket_path()
    if not sock_path.exists():
        return None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(str(sock_path))
        return sock
    except (OSError, TimeoutError):
        return None


def send_request(sock: socket.socket, request: dict[str, Any], timeout: float = 120.0) -> dict[str, Any] | None:
    """Send JSON-line request, read JSON-line response."""
    try:
        sock.settimeout(timeout)
        sock.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")

        data = b""
        while b"\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                return None
            data += chunk

        line = data.split(b"\n", 1)[0]
        result: dict[str, Any] = json.loads(line)
        return result
    except (OSError, TimeoutError, json.JSONDecodeError):
        return None
    finally:
        sock.close()


def ping() -> dict[str, Any] | None:
    """Ping daemon. Returns response dict or None if unreachable."""
    sock = connect()
    if sock is None:
        return None
    return send_request(sock, {"cmd": "ping"}, timeout=5.0)


def _code_key(code: str) -> tuple[Any, int] | None:
    """`(package version, map version)` of a code identity, or None when it does not parse."""
    from packaging.version import InvalidVersion, Version

    package, sep, mapper = code.rpartition("+map")
    try:
        return (Version(package), int(mapper)) if sep else None
    except (InvalidVersion, ValueError):
        return None


def runs_older_code(pong: dict[str, Any]) -> bool:
    """Whether a daemon reply comes from an older version than this process: one from before
    the reply carried its code, or one whose package or map version is lower."""
    from reporails_cli.core.mapper.daemon import code_identity

    code = pong.get("code")
    if not isinstance(code, str):
        return True
    theirs, ours = _code_key(code), _code_key(code_identity())
    return theirs is not None and ours is not None and theirs < ours


def runs_newer_code(pong: dict[str, Any]) -> bool:
    """Whether a daemon reply comes from a newer version than this process."""
    from reporails_cli.core.mapper.daemon import code_identity

    code = pong.get("code")
    theirs = _code_key(code) if isinstance(code, str) else None
    ours = _code_key(code_identity())
    return theirs is not None and ours is not None and theirs > ours


def serves_this_code(pong: dict[str, Any] | None) -> bool:
    """Whether a daemon reply (a ping or a map) comes from a daemon that maps with this
    process's code.

    Another installed version's daemon (or one from before the reply carried its code) maps
    with its own mapper, so its map is not this version's.
    """
    from reporails_cli.core.mapper.daemon import code_identity

    return pong is not None and pong.get("code") == code_identity()


def _stream_map_response(
    sock: socket.socket,
    request: dict[str, Any],
    progress: Callable[[str], None] | None,
    timeout: float,
) -> dict[str, Any] | None:
    """Send a map request, forward streamed progress lines, return the result line.

    Reads newline-delimited JSON objects: a ``{"type": "progress", "msg": ...}``
    line is handed to ``progress`` and reading continues; the first line carrying
    ``ok`` is the result and is returned. Returns None on timeout, socket error,
    a malformed line, or a stream that closes before the result arrives.
    """
    try:
        sock.settimeout(timeout)
        sock.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")

        buf = b""
        while True:
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    return None  # stream closed before a result line
                buf += chunk
            line, buf = buf.split(b"\n", 1)
            if not line.strip():
                continue
            obj: dict[str, Any] = json.loads(line)
            if obj.get("type") == "progress":
                if progress is not None:
                    # A spinner/render error in the caller's callback must never
                    # abort the map or the result read — swallow and keep reading.
                    try:
                        progress(str(obj.get("msg", "")))
                    except Exception:
                        logger.debug("map progress callback raised; ignoring", exc_info=True)
                continue
            return obj  # the result line (carries `ok`)
    except (OSError, TimeoutError, json.JSONDecodeError):
        return None
    finally:
        sock.close()


def map_ruleset_via_daemon(
    paths: list[Path],
    root: Path,
    progress: Callable[[str], None] | None = None,
) -> Any:
    """Map ruleset via global daemon. Returns RulesetMap or None on failure.

    Caller should fall back to in-process mapping when this returns None.

    The daemon streams JSON lines: zero or more ``{"type": "progress", "msg": ...}``
    lines (forwarded to ``progress`` so the caller's spinner advances per harness
    element on the daemon path too, not just in-process), followed by the single
    result line carrying ``ok`` + ``ruleset_map``. A malformed line or a closed
    stream before the result yields None so the caller falls back to in-process.
    """
    sock = connect()
    if sock is None:
        return None

    request = {
        "cmd": "map_ruleset",
        "paths": [str(p) for p in paths],
        "root": str(root),
    }
    # Matches the daemon-side connection timeout; covers a cold model load and the
    # first encode, plus mapping work, with headroom.
    response = _stream_map_response(sock, request, progress, timeout=300.0)
    if response is None or not response.get("ok"):
        logger.debug("Daemon map_ruleset failed: %s", response.get("error") if response else "no response")
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
        import tempfile

        from reporails_cli.core.mapper.serialize import load_ruleset_map

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(map_data, f)
            tmp_path = Path(f.name)

        result = load_ruleset_map(tmp_path)
        tmp_path.unlink()
        return result
    except (OSError, TimeoutError, json.JSONDecodeError, RuntimeError):
        logger.debug("Failed to deserialize daemon response", exc_info=True)
        return None


def ensure_daemon(emit: Callable[[str], None] | None = None) -> DaemonStatus:
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
    from reporails_cli.core.mapper.daemon import daemon_pid, is_daemon_running, retire_daemon, start_daemon

    say = emit if emit is not None else (lambda _msg: None)

    if is_daemon_running():
        # One busy mapping misses the ping; it is attached as before, and a map it returns from
        # other code is refused on arrival. A daemon that answers with other code is never used:
        # an older version's (left over from before an upgrade) is replaced by this version's
        # once it has exited, a newer version's is left to that version.
        pong = ping()
        if pong is None or serves_this_code(pong):
            return DaemonStatus.ATTACHED
        if not runs_older_code(pong):
            return DaemonStatus.UNAVAILABLE
        # Not retired because it is busy or slow to exit: leave it. Not retired because it is
        # already gone or replaced (a check running beside this one got there first): start or
        # attach to this version's below.
        if not retire_daemon(pong.get("pid")) and daemon_pid() == pong.get("pid"):
            return DaemonStatus.UNAVAILABLE

    say("Starting Reporails...")
    try:
        start_daemon()
    except OSError:
        return DaemonStatus.UNAVAILABLE

    if not is_daemon_running():
        return DaemonStatus.UNAVAILABLE

    say("Loading tools...")
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if ping() is not None:
            return DaemonStatus.STARTED
        time.sleep(0.05)
    return DaemonStatus.STARTING
