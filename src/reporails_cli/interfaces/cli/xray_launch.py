"""How a launched x-ray page runs: its socket, the clock of its requests and when it stops for want of one."""

from __future__ import annotations

import socket
import threading
import time

import typer
import uvicorn
from starlette.types import ASGIApp, Receive, Scope, Send

from reporails_cli.core.xray.pages import HOST


class RequestClock:
    """When the page last received a request."""

    def __init__(self) -> None:
        self._last = time.monotonic()

    def mark(self) -> None:
        """Record a request now."""
        self._last = time.monotonic()

    def quiet_s(self) -> float:
        """Seconds since the last request."""
        return time.monotonic() - self._last


def mark_requests(app: ASGIApp, requests: RequestClock) -> ASGIApp:
    """`app` with every HTTP request marked on the clock before it is passed on."""

    async def marked(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            requests.mark()
        await app(scope, receive, send)

    return marked


def bound_socket() -> socket.socket:
    """A listening socket on `127.0.0.1` at a free port, so the port is known before the page address prints."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    sock.listen(16)
    return sock


def _stop_when_idle(server: uvicorn.Server, requests: RequestClock, idle_s: int, stopped: threading.Event) -> None:
    """Tell the server to stop once no request has come for `idle_s` seconds, and set `stopped`."""
    while (left := idle_s - requests.quiet_s()) > 0:
        time.sleep(left)
    stopped.set()
    server.should_exit = True


def span(seconds: int) -> str:
    """`seconds` in whole minutes when it is one, else in seconds."""
    count, unit = (seconds // 60, "minute") if seconds % 60 == 0 else (seconds, "second")
    return f"{count} {unit}{'' if count == 1 else 's'}"


def run_until_idle(server: uvicorn.Server, sock: socket.socket, requests: RequestClock, idle_s: int | None) -> None:
    """Serve on `sock` until stopped, stopping after `idle_s` seconds with no request when given; say so when that
    is why it stopped."""
    idle_stop = threading.Event()
    if idle_s is not None:
        threading.Thread(target=_stop_when_idle, args=(server, requests, idle_s, idle_stop), daemon=True).start()
    server.run(sockets=[sock])
    if idle_s is not None and idle_stop.is_set():
        typer.echo(f"The x-ray page stopped: no request for {span(idle_s)}.")
