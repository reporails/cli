"""The server verdict gate on the x-ray launch check and in the gate itself, against a local service stand-in.

The `ails check` and MCP surfaces are demonstrated by `tests/behave/server_gate.feature`; the x-ray launch
check has no console entry that runs without a browser, so it is driven here through its own method.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from reporails_cli.core.pipeline.server_gate import server_gate
from reporails_cli.interfaces.cli import xray_server

pytestmark = [pytest.mark.integration, pytest.mark.subsys_xray, pytest.mark.usefixtures("server_reachable")]

_REFUSED = {"verdict": "refused", "reason": "rate", "message": "Hourly limit reached. Run `ails login`."}


class _Stand(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        self.server.seen.append((self.path, self.headers.get("X-Reporails-Surface")))  # type: ignore[attr-defined]
        raw = json.dumps(self.server.body).encode()  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Stand)
    server.seen = []  # type: ignore[attr-defined]
    server.body = _REFUSED  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("AILS_SERVER_URL", f"http://127.0.0.1:{server.server_address[1]}")
    yield server
    server.shutdown()
    server.server_close()


def _launch(root: Path) -> tuple[object, dict[str, object]]:
    page = xray_server.XrayServer(root.resolve(), root / "s.jsonl", picked="newest", token="t", launch="l", port=8765)
    return page._launch_outcome()


def test_a_refused_launch_check_is_refused_with_the_servers_words_and_the_xray_surface(
    service: ThreadingHTTPServer, tmp_path: Path
) -> None:
    (tmp_path / "CLAUDE.md").write_text("# P\n\nUse uv.\n", encoding="utf-8")
    check, tallies = _launch(tmp_path)
    assert (check.state, check.message) == ("refused", _REFUSED["message"])  # type: ignore[attr-defined]
    assert tallies == {}
    assert service.seen == [("/v1/handshake", "xray")]  # type: ignore[attr-defined]


def test_nothing_is_asked_when_offline_is_requested_or_the_run_talks_to_a_local_server(
    service: ThreadingHTTPServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AILS_OFFLINE", "1")
    assert server_gate("cli") is None
    monkeypatch.delenv("AILS_OFFLINE")
    monkeypatch.setenv("AILS_DEV_MODE", "1")
    assert server_gate("cli") is None
    assert service.seen == []  # type: ignore[attr-defined]


def test_a_served_caller_is_not_refused_and_a_refused_one_gets_the_servers_message(
    service: ThreadingHTTPServer,
) -> None:
    refusal = server_gate("cli")
    assert refusal is not None and (refusal.kind, refusal.message) == ("server_refused", _REFUSED["message"])
    service.body = {"verdict": "ok", "reason": None, "message": None, "tier": "free"}  # type: ignore[attr-defined]
    assert server_gate("cli") is None
