"""Step definitions for the server-verdict behavioral demonstrations.

A small `http.server` in a thread plays the diagnostics service on an ephemeral port: it answers the
handshake as the scenario says, answers a diagnosis with an error, and records every request it is
asked (method, path, surface header). The real `ails` binary (and the real MCP server) run against it
with `AILS_SERVER_URL` pointed there and `HOME` pointed at the scenario's temp dir. Nothing reaches a
production address: the model download address points at the same stand-in.
"""

from __future__ import annotations

import json
import socket
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from behave import given, then, when  # type: ignore[import-untyped]
from support import daemon_started, run_ails, run_mcp_validate

_SIGN_UP = (
    "Hourly limit reached. Sign up with `ails login` (reporails.com/account) for a free API key "
    "to use in CI. The limit resets in 12 minutes."
)
_UPDATE = "This version of ails is no longer supported. Run `ails update`."


def _handshake_body(verdict: str, reason: str | None = None, message: str | None = None) -> dict[str, object]:
    return {
        "verdict": verdict,
        "reason": reason,
        "message": message,
        "tier": "anonymous",
        "limit": 60,
        "remaining": 0 if verdict == "refused" else 59,
        "reset_in": 720,
        "file_limit": 100,
        "files_remaining": 100,
        "minimum_version": "0.6.2",
        "latest_version": None,
    }


class _Service(BaseHTTPRequestHandler):
    """The service stand-in; the server object carries the scenario's state."""

    def log_message(self, format: str, *args: object) -> None:
        return

    def _answer(self, status: int, body: object) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _route(self, method: str) -> None:
        state = self.server.state  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        state["requests"].append((method, self.path, self.headers.get("X-Reporails-Surface")))
        if method == "GET" and self.path == "/v1/handshake":
            self._answer(*state["handshake"])
        elif method == "POST" and self.path == "/v1/diagnose":
            self._answer(*state["diagnose"])
        else:
            self._answer(404, {"error": "not_found"})

    def do_GET(self) -> None:
        self._route("GET")

    def do_POST(self) -> None:
        self._route("POST")


_NO_DIAGNOSIS = (500, {"error": "stand_in", "message": "no diagnosis from the stand-in"})


def _serve(context, handshake: tuple[int, object], diagnose: tuple[int, object] = _NO_DIAGNOSIS) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Service)
    server.state = {"requests": [], "handshake": handshake, "diagnose": diagnose}  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    context.service = server
    context.service_url = f"http://127.0.0.1:{server.server_address[1]}"
    context.watch_model_fetch = False
    context.add_cleanup(server.shutdown)
    context.add_cleanup(server.server_close)


def _requests(context) -> list[tuple[str, str, str | None]]:
    return list(context.service.state["requests"])


@given("a service that refuses an anonymous caller for the hourly limit")
def step_refuses_rate(context) -> None:
    _serve(context, (200, _handshake_body("refused", "rate", _SIGN_UP)))
    context.watch_model_fetch = True


@given("a service that refuses an out-of-date version")
def step_refuses_version(context) -> None:
    _serve(context, (200, _handshake_body("refused", "version", _UPDATE)))
    context.watch_model_fetch = True


@given("a service that rejects the credential")
def step_rejects(context) -> None:
    body = {"error": "invalid_api_key", "message": "That API key is not valid."}
    _serve(context, (401, body))
    context.watch_model_fetch = True
    context.extra_env = {"AILS_API_KEY": "rai_not_a_real_key"}


@given("a service that rejects the credential saved a moment ago")
def step_rejects_fresh(context) -> None:
    key = "rai_not_a_real_key"
    rejection = (401, {"error": "invalid_api_key", "message": "That API key is not valid."})
    _serve(context, rejection, rejection)
    context.extra_env = {"AILS_API_KEY": key}
    record = {"api_key": key, "signed_in_at": datetime.now(UTC).isoformat()}
    path = context.home / ".reporails" / "credentials.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record), encoding="utf-8")


@given("a service that accepts the caller")
def step_accepts(context) -> None:
    _serve(context, (200, _handshake_body("ok")))


@given("a service that answers the handshake with HTTP {status:d}")
def step_other_status(context, status: int) -> None:
    _serve(context, (status, {"error": "stand_in"}))


@given("no service is listening")
def step_nothing_listening(context) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    context.service_url = f"http://127.0.0.1:{port}"
    context.service = None
    context.watch_model_fetch = True


def _env(context, extra: dict[str, str] | None = None) -> dict[str, str]:
    """The binary's environment: the stand-in as the service, offline mode off, the model download pointed
    at the stand-in when the scenario watches for one (otherwise never attempted)."""
    env = {"AILS_SERVER_URL": context.service_url, "AILS_OFFLINE": "", **getattr(context, "extra_env", {})}
    if context.watch_model_fetch:
        env.update({"AILS_MODEL_OFFLINE": "", "AILS_MODEL_URL": f"{context.service_url}/models"})
        models = context.home / ".reporails" / "cache" / "models"
        if models.is_symlink():
            models.unlink()  # the shared model cache would hide a fetch: the home starts with none
    return {**env, **(extra or {})}


def _run(context, command: str, extra: dict[str, str] | None = None) -> None:
    parts = command.split()
    assert parts[0] == "ails", command
    cwd = context.project or context.tmpdir
    context.result = run_ails(cwd, *parts[1:], home=context.home, timeout=90, env=_env(context, extra))


@when('I invoke "{command}" against the service')
def step_run(context, command: str) -> None:
    _run(context, command)


@when('with {name} set to "{value}" I invoke "{command}" against the service')
def step_run_with_env(context, name: str, value: str, command: str) -> None:
    _run(context, command, {name: value})


@when("the MCP validate tool runs against the service")
def step_mcp(context) -> None:
    env = {**_env(context), "AILS_MODEL_OFFLINE": "1"}  # the server's own launch-time fetch is not under test
    context.mcp_reply = run_mcp_validate(context.project, home=context.home, env=env)


@then("the run exits {code:d}")
def step_exit(context, code: int) -> None:
    result = context.result
    assert result.returncode == code, f"exit {result.returncode}\n{result.stdout}\n{result.stderr}"


def _output(context) -> str:
    return context.result.stdout + context.result.stderr


@then('the output says "{text}"')
def step_says(context, text: str) -> None:
    assert text in " ".join(_output(context).split()), _output(context)


@then('the stdout is a json error "{kind}" saying "{text}"')
def step_json_error(context, kind: str, text: str) -> None:
    body = json.loads(context.result.stdout)
    assert body["error"] == kind, body
    assert text in body["message"], body


@then('the stdout is one "{prefix}" line saying "{text}"')
def step_github_line(context, prefix: str, text: str) -> None:
    lines = context.result.stdout.strip().splitlines()
    assert len(lines) == 1 and lines[0].startswith(prefix) and text in lines[0], context.result.stdout


@then('the MCP reply is the error "{kind}" saying "{text}"')
def step_mcp_error(context, kind: str, text: str) -> None:
    assert context.mcp_reply["error"] == kind, context.mcp_reply
    assert text in context.mcp_reply["message"], context.mcp_reply


@then("the service was asked only for the handshake")
def step_only_handshake(context) -> None:
    assert [(m, p) for m, p, _ in _requests(context)] == [("GET", "/v1/handshake")], _requests(context)


@then("the service was asked nothing")
def step_nothing(context) -> None:
    assert _requests(context) == [], _requests(context)


@then("the service was asked for the handshake and then for the diagnosis")
def step_both(context) -> None:
    assert [(m, p) for m, p, _ in _requests(context)] == [("GET", "/v1/handshake"), ("POST", "/v1/diagnose")], (
        _requests(context)
    )


@then("the service was asked for the handshake and the run went on to its local result")
def step_handshake_then_local(context) -> None:
    asked = [(m, p) for m, p, _ in _requests(context)]
    assert asked and asked[0] == ("GET", "/v1/handshake"), _requests(context)
    assert "Findings" in _output(context), _output(context)


@then('the service saw the surface "{surface}"')
def step_surface(context, surface: str) -> None:
    assert [s for m, p, s in _requests(context) if p == "/v1/handshake"] == [surface], _requests(context)


@then("the service saw no handshake")
def step_no_handshake(context) -> None:
    assert [p for _, p, _ in _requests(context) if "handshake" in p] == [], _requests(context)


@then("no model was fetched and no file was discovered")
def step_no_local_work(context) -> None:
    home = context.home / ".reporails"
    models = home / "cache" / "models"
    assert not models.exists() or not any(models.iterdir()), list(models.iterdir())
    if context.service is not None:
        assert not [p for _, p, _ in _requests(context) if p.startswith("/models")], _requests(context)
    assert not daemon_started(context.home), "a mapper daemon was started"
    assert "CLAUDE.md" not in _output(context), _output(context)
    assert Path(context.project / "CLAUDE.md").exists()
