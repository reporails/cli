"""CLI/MCP parity on a genuine server-side error response.

`ails check -f json` and MCP `validate` both report `offline` + `server_error` for a run
whose server round-trip fails. This gate starts a small local HTTP server that always
answers with an error status (no parseable diagnostics body) and checks that both
surfaces read the outcome the same way: `offline: true`, with the same `server_error`
reason — for a 404 (route not found, e.g. hitting the wrong diagnostics path) and for a
500 (a server-side failure), the two statuses a "server answered, but not with a
diagnostics report" run can carry.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app
from reporails_cli.interfaces.mcp import tools

runner = CliRunner()

_has_onnx_model = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
).exists()
requires_model = pytest.mark.skipif(not _has_onnx_model, reason="Bundled ONNX model not available")


def _rules_installed() -> bool:
    from reporails_cli.core.platform.config.bootstrap import get_rules_path

    return (get_rules_path() / "core").exists()


requires_rules = pytest.mark.skipif(not _rules_installed(), reason="Rules framework not installed")


class _ErrorHandler(BaseHTTPRequestHandler):
    """Answers every request with this handler class's `status_code`, no diagnostics body."""

    status_code = 404

    def _respond(self) -> None:
        body = b"{}"
        self.send_response(self.status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        self._respond()

    def do_GET(self) -> None:
        self._respond()

    def log_message(self, format: str, *args: object) -> None:
        pass  # keep test output clean


@contextmanager
def _stub_error_server(status_code: int) -> Iterator[str]:
    """Start a server on an ephemeral port that always answers `status_code`; yields its base URL."""
    handler_cls = type(f"_ErrorHandler{status_code}", (_ErrorHandler,), {"status_code": status_code})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _isolate_global_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point the global config at a path that can't exist, so the machine's real
    `~/.reporails/config.yml` never leaks a `default_agent` / `tier` into this fixture."""
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_config_path",
        lambda: tmp_path / "unused-global-config.yml",
    )


def _make_project(tmp_path: Path) -> Path:
    """A `.claude/rules/*.md`-only tree: a distinctive-enough project to take the normal
    (non-empty-instruction-files) run path on both surfaces, so a server round-trip is
    genuinely attempted."""
    project = tmp_path / "proj"
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / ".claude" / "rules" / "style.md").write_text(
        "# Style\n\nStyle guidance for agents working in this repository.\n", encoding="utf-8"
    )
    return project


def _cli_payload(project: Path) -> dict:
    cwd = os.getcwd()
    os.chdir(project)
    try:
        result = runner.invoke(app, ["check", "-f", "json"])
    finally:
        os.chdir(cwd)
    assert result.exit_code in (0, 1), result.output
    return json.loads(result.output)


@requires_model
@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
@pytest.mark.parametrize("status_code", [404, 500])
def test_cli_and_mcp_agree_offline_and_server_error_on_a_server_error_response(
    status_code: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server that answers (404 or 500) but never produces a diagnostics report must read
    as `offline: true` with a matching `server_error` on BOTH surfaces — a real HTTP status
    on the rejection must not flip MCP's `offline` to `false` while the CLI still reports
    `true` for the identical run."""
    _isolate_global_config(monkeypatch, tmp_path)
    project = _make_project(tmp_path)

    with _stub_error_server(status_code) as server_url:
        monkeypatch.setenv("AILS_SERVER_URL", server_url)
        cli_payload = _cli_payload(project)
        mcp_payload = tools.validate_tool(str(project), full=True)

    assert cli_payload["offline"] is True, cli_payload
    assert mcp_payload["offline"] is True, mcp_payload
    assert cli_payload["offline"] == mcp_payload["offline"]
    assert cli_payload.get("server_error") is not None, cli_payload
    assert cli_payload.get("server_error") == mcp_payload.get("server_error")
