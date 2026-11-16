"""The mapper daemon's Unix socket: JSON-line frames behind the `DaemonTransport` contract."""

from __future__ import annotations

import contextlib
import json
import logging
import signal
import socket
import sys
import time
from collections.abc import Callable
from pathlib import Path

from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_object
from reporails_cli.core.platform.utils.utils import compact_json

logger = logging.getLogger(__name__)

# Seconds a connection to the daemon socket may take.
_CONNECT_TIMEOUT_S = 5.0
# Seconds a client may take to send its request.
_REQUEST_TIMEOUT_S = 300.0
_BACKLOG = 2
_ACCEPT_POLL_S = 1.0
_MAX_REQUEST_BYTES = 10_000_000  # 10MB
_CHUNK = 65536


def _frame(obj: JsonObject) -> bytes:
    return compact_json(obj).encode() + b"\n"


class UnixDaemonSocket:
    """Reaches and serves the daemon over a Unix domain socket, one JSON object per line."""

    def exchange(
        self,
        address: Path,
        request: JsonObject,
        *,
        timeout: float,
        on_message: Callable[[JsonObject], None] | None,
    ) -> JsonObject:
        """Send `request` to the socket at `address`; the first frame that is not progress is the reply.

        Raises `PlatformUnavailableError` when the socket does not answer.
        """
        if sys.platform == "win32" or not address.exists():
            raise PlatformUnavailableError(f"no daemon socket at {address}")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(_CONNECT_TIMEOUT_S)
                sock.connect(str(address))
                sock.settimeout(timeout)
                sock.sendall(_frame(request))
                return _read_reply(sock, on_message)
        except (OSError, TimeoutError, json.JSONDecodeError) as exc:
            raise PlatformUnavailableError(f"the daemon at {address} did not answer: {exc}") from exc

    def serve(
        self,
        address: Path,
        handle: Callable[[JsonObject, Callable[[JsonObject], None]], JsonObject],
        *,
        idle_timeout: int | None,
    ) -> None:
        """Bind `address` and answer one connection at a time until a signal or the idle timeout."""
        stopped = False

        def _stop(_signum: int, _frame: object) -> None:
            nonlocal stopped
            stopped = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        # A half-closed client must not kill the server: the write raises BrokenPipeError instead.
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(address))
            server.listen(_BACKLOG)
            server.settimeout(_ACCEPT_POLL_S)
            last_activity = time.monotonic()
            while not stopped:
                if idle_timeout is not None and time.monotonic() - last_activity > idle_timeout:
                    return
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                last_activity = time.monotonic()
                try:
                    _answer(conn, handle)
                except Exception:  # pylint: disable=broad-exception-caught  # one failed request must not stop the daemon serving
                    logger.warning("daemon request failed", exc_info=True)
                finally:
                    conn.close()


def _read_reply(sock: socket.socket, on_message: Callable[[JsonObject], None] | None) -> JsonObject:
    """Read frames until the first one that is not progress; progress frames go to `on_message`."""
    buf = b""
    while True:
        while b"\n" not in buf:
            chunk = sock.recv(_CHUNK)
            if not chunk:
                raise PlatformUnavailableError("the daemon closed the connection before a reply")
            buf += chunk
        line, buf = buf.split(b"\n", 1)
        if not line.strip():
            continue
        parsed: JsonValue = json.loads(line)
        if not isinstance(parsed, dict):
            raise PlatformUnavailableError("the daemon sent a frame that is not a JSON object")
        if parsed.get("type") != "progress":
            return parsed
        if on_message is not None:
            on_message(parsed)


def _answer(conn: socket.socket, handle: Callable[[JsonObject, Callable[[JsonObject], None]], JsonObject]) -> None:
    """Read one request from `conn`, hand it to `handle`, write the reply."""
    conn.settimeout(_REQUEST_TIMEOUT_S)  # enough for cold warmup + map
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(_CHUNK)
        if not chunk:
            return
        data += chunk
        if len(data) > _MAX_REQUEST_BYTES:
            conn.sendall(_frame({"ok": False, "error": "request too large"}))
            return

    invalid = False
    try:
        decoded: JsonValue = json.loads(data.split(b"\n", 1)[0])
    except json.JSONDecodeError:
        decoded = None
        invalid = True
    if invalid:
        conn.sendall(_frame({"ok": False, "error": "invalid JSON"}))
        return
    request = as_object(decoded)

    def _send(frame: JsonObject) -> None:
        # A closed or half-open client raises here; a frame that cannot be written must never abort the request.
        with contextlib.suppress(OSError):
            conn.sendall(_frame(frame))

    conn.sendall(_frame(handle(request, _send)))
