"""Step definitions for the `ails login` / `ails logout` behavioral demonstrations.

A tiny `http.server` in a thread plays the website: it answers the sign-in start, then
"authorization_pending" once, then the approval, and records what it was asked. The real
`ails` binary runs against it with `AILS_PLATFORM_URL` pointed there and `HOME` pointed at
the scenario's temp dir. No in-process `CliRunner`, no stubbed code.
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml
from behave import given, then, when  # type: ignore[import-untyped]
from support import run_ails

_TOKEN = "tok-issued-by-the-stub"


class _Website(BaseHTTPRequestHandler):
    """The website stand-in; the server object carries the scenario's state."""

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: int, body: object | None = None) -> None:
        raw = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        state = self.server.state  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        if self.path == "/oauth/device_authorization":
            self._send(
                200,
                {
                    "device_code": "dev-1",
                    "user_code": "ABCD-EFGH",
                    "verification_uri_complete": f"{state['site']}/oauth/device?user_code=ABCD-EFGH",
                    "expires_in": 600,
                    "interval": 1,
                },
            )
        elif self.path == "/oauth/token":
            state["token_asks"] += 1
            if state["token_asks"] == 1:
                self._send(400, {"error": "authorization_pending"})
            else:
                self._send(
                    200,
                    {
                        "access_token": _TOKEN,
                        "expires_in": 31536000,
                        "account": {"login": "octo", "tier": "pro"},
                        "machine": "behave",
                        "notices": [],
                    },
                )
        elif self.path == "/api/auth/logout":
            state["revoked"].append(self.headers.get("Authorization", ""))
            self._send(204)
        else:
            self._send(404, {"error": "not_found"})


def _home(context) -> Path:
    home = context.tmpdir / "home"
    home.mkdir(exist_ok=True)
    return home


@given("a website that approves the sign-in after one pending answer")
def step_website(context) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Website)
    site = f"http://127.0.0.1:{server.server_address[1]}"
    server.state = {"site": site, "token_asks": 0, "revoked": []}  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    context.website = server
    context.add_cleanup(server.shutdown)
    context.add_cleanup(server.server_close)


@when('I run "{command}" against that website')
def step_run(context, command: str) -> None:
    parts = command.split()
    assert parts[0] == "ails", command
    home = _home(context)
    env = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "AILS_PLATFORM_URL": context.website.state["site"],
        "AILS_API_KEY": "",
        # The login opens a browser whenever the machine can show one: point it at a command that succeeds
        # and does nothing, and hide any screen, so a developer's real browser never opens.
        "BROWSER": f'"{Path(sys.executable).as_posix()}" -c pass %s',
        "DISPLAY": "",
        "WAYLAND_DISPLAY": "",
    }
    context.result = run_ails(home, *parts[1:], timeout=60, env=env)


@then("the login exits {code:d}")
def step_exit(context, code: int) -> None:
    result = context.result
    assert result.returncode == code, f"exit {result.returncode}\n{result.stdout}\n{result.stderr}"


@then('the login output says "{text}"')
def step_says(context, text: str) -> None:
    assert text in context.result.stdout, context.result.stdout


@then('the login output shows the code "{code}"')
def step_code(context, code: str) -> None:
    assert f"Code: {code}" in context.result.stdout, context.result.stdout


def _stored(context) -> Path:
    return _home(context) / ".reporails" / "credentials.yml"


@then('the stored sign-in holds the issued token for "{account}"')
def step_stored(context, account: str) -> None:
    record = yaml.safe_load(_stored(context).read_text(encoding="utf-8"))
    assert record["api_key"] == _TOKEN
    assert record["account"] == account
    assert record["tier"] == "pro"
    assert record["signed_in_at"]


@then("the website was asked twice for the token")
def step_asks(context) -> None:
    assert context.website.state["token_asks"] == 2


@then("the website revoked the issued token")
def step_revoked(context) -> None:
    assert context.website.state["revoked"] == [f"Bearer {_TOKEN}"]


@then("no sign-in is stored")
def step_none(context) -> None:
    assert not _stored(context).exists()
