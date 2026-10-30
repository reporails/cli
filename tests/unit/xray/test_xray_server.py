"""The x-ray page server: every guard refuses before a core call, the routes translate, the page loads offline."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.testclient import TestClient

from reporails_cli.core.heal.apply import HealOutcome
from reporails_cli.core.heal.keyed import KeyedResult
from reporails_cli.core.pipeline.check_one import Refusal
from reporails_cli.core.pipeline.mapping import map_instruction_files
from reporails_cli.core.platform.adapters.workflow_wire import deserialize_workflow
from reporails_cli.core.platform.dto.diagnostics import FindingItem
from reporails_cli.interfaces.cli import xray_server
from tests.unit.test_mcp_heal_apply import DOC, _wire

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript" / "2.1.308"
TOKEN = "launch-token"
PORT = 8765
ORIGIN = f"http://127.0.0.1:{PORT}"
TOP_KEYS = {
    "version", "session", "project", "started_at", "length_s", "window", "first_context",
    "start", "turns", "subagents", "artifacts", "refusals", "not_known",
}  # fmt: skip
HEAVY = ("starlette", "uvicorn", "reporails_cli.core.mapper", "onnxruntime", "tokenizers", "numpy")


class Calls:
    """What the fake core was asked."""

    def __init__(self) -> None:
        self.checked: list[str] = []
        self.healed: list[str] = []


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "CLAUDE.md").write_text("# Rules\n\nRun `pytest` before committing.\n")
    (tmp_path / "outside.md").write_text("# Outside\n")
    (root / "link.md").symlink_to(tmp_path / "outside.md")
    copy = tmp_path / "session"
    shutil.copytree(FIXTURES, copy)
    for file in copy.rglob("*.jsonl"):
        file.write_text(file.read_text().replace("/work/proj", str(root)))
    return root


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> Calls:
    seen = Calls()

    def fake_check(path: str) -> Refusal:
        seen.checked.append(path)
        return Refusal("failed", "fake refusal")

    def fake_heal(path: str) -> HealOutcome:
        seen.healed.append(path)
        return HealOutcome(KeyedResult(), "", Path(path).parent)

    monkeypatch.setattr(xray_server, "check_path", fake_check)
    monkeypatch.setattr(xray_server, "heal_one", fake_heal)
    return seen


@pytest.fixture
def client(project: Path, tmp_path: Path) -> TestClient:
    app = xray_server.build_app(project, tmp_path / "session" / "session.jsonl", TOKEN, PORT)
    return TestClient(app, base_url=ORIGIN)


def _post(client: TestClient, route: str, body: object, **headers: str) -> int:
    sent = {"X-Xray-Token": TOKEN, "Origin": ORIGIN, **headers}
    return client.post(route, json=body, headers=sent).status_code


@pytest.mark.parametrize("route", ["/check", "/heal"])
@pytest.mark.parametrize("token", [None, "wrong"])
def test_a_post_without_the_launch_token_is_refused_before_the_core(
    client: TestClient, calls: Calls, route: str, token: str | None
) -> None:
    headers = {"Origin": ORIGIN} | ({"X-Xray-Token": token} if token else {})
    assert client.post(route, json={"path": "CLAUDE.md"}, headers=headers).status_code == 403
    assert calls.checked == [] and calls.healed == []


@pytest.mark.parametrize("token", [None, "wrong"])
def test_view_without_the_launch_token_is_refused(client: TestClient, token: str | None) -> None:
    assert client.get("/view", headers={"X-Xray-Token": token} if token else {}).status_code == 403


@pytest.mark.parametrize("origin", ["http://evil.example", "http://127.0.0.1:1", None])
def test_a_post_from_a_foreign_or_absent_origin_is_refused_before_the_core(
    client: TestClient, calls: Calls, origin: str | None
) -> None:
    headers = {"X-Xray-Token": TOKEN} | ({"Origin": origin} if origin else {})
    assert client.post("/check", json={"path": "CLAUDE.md"}, headers=headers).status_code == 403
    assert calls.checked == []


def test_a_foreign_host_is_refused(client: TestClient) -> None:
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400


def test_only_the_fixed_routes_exist(client: TestClient) -> None:
    assert client.get("/etc/passwd").status_code == 404
    assert client.get("/check").status_code == 405
    assert client.post("/view").status_code == 405


@pytest.mark.parametrize("body", [{"path": "CLAUDE.md", "extra": 1}, {}, {"path": 3}, ["CLAUDE.md"]])
def test_a_body_with_anything_but_a_path_is_refused_before_the_core(
    client: TestClient, calls: Calls, body: object
) -> None:
    assert _post(client, "/check", body) == 400
    assert calls.checked == []


@pytest.mark.parametrize("route", ["/check", "/heal"])
@pytest.mark.parametrize("path", ["../outside.md", "link.md", "missing.md", "."])
def test_a_path_outside_the_project_or_not_a_file_is_refused_before_the_core(
    client: TestClient, calls: Calls, route: str, path: str
) -> None:
    assert _post(client, route, {"path": path}) == 400
    assert calls.checked == [] and calls.healed == []


def test_check_reports_a_refusal_as_400_and_a_file_as_its_findings(
    client: TestClient, project: Path, calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    reply = client.post("/check", json={"path": "CLAUDE.md"}, headers={"X-Xray-Token": TOKEN, "Origin": ORIGIN})
    assert reply.status_code == 400 and reply.json() == {"error": "fake refusal"}
    assert calls.checked == [str((project / "CLAUDE.md").resolve())]

    class Run:
        pass

    finding = FindingItem(file="CLAUDE.md", line=3, severity="warning", rule="CORE:C:0001", message="Say it plainly")
    monkeypatch.setattr(xray_server, "check_path", lambda path: Run())
    monkeypatch.setattr(xray_server, "file_findings", lambda run, file: (finding,))
    reply = client.post("/check", json={"path": "CLAUDE.md"}, headers={"X-Xray-Token": TOKEN, "Origin": ORIGIN})
    assert reply.json()["findings"] == 1
    assert reply.json()["lines"] == [{"line": 3, "rule": "CORE:C:0001", "message": "Say it plainly"}]
    view = client.get("/view", headers={"X-Xray-Token": TOKEN}).json()
    artifact = next(a for a in view["artifacts"] if a["path"].endswith("CLAUDE.md"))
    assert artifact["findings"] == 1


def test_heal_replies_with_the_receipt_or_the_reason_nothing_was_written(
    client: TestClient, calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = {"X-Xray-Token": TOKEN, "Origin": ORIGIN}
    reply = client.post("/heal", json={"path": "CLAUDE.md"}, headers=headers).json()
    assert reply["receipt"][0].startswith("heal_apply: 0 fixed")
    monkeypatch.setattr(
        xray_server, "heal_one", lambda path: HealOutcome(None, "Applying fixes needs a Pro account.", Path())
    )
    reply = client.post("/heal", json={"path": "CLAUDE.md"}, headers=headers).json()
    assert reply["receipt"] == ["Applying fixes needs a Pro account."]


def _real_heal(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Leave `heal_one` and the keyed write real; only the server-backed check returns a fixture run."""
    path = project / "CLAUDE.md"
    path.write_text(DOC)
    m = map_instruction_files(project, [path], spawn_daemon=False)
    wire = _wire(project, m, ((3, "unbold", "bold"), (7, "code", "format")))
    reply = SimpleNamespace(workflow=deserialize_workflow({"workflow": wire}), tier="pro")
    result = SimpleNamespace(reply=reply, offline=False)
    run = SimpleNamespace(ruleset_map=m, result=result, funnel_error=None, scope=SimpleNamespace(scan_root=project))
    monkeypatch.setattr("reporails_cli.core.heal.apply.check_path", lambda _path: run)


@pytest.mark.requires_model
def test_heal_button_writes_every_fix_through_the_real_heal(
    client: TestClient, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _real_heal(project, monkeypatch)
    headers = {"X-Xray-Token": TOKEN, "Origin": ORIGIN}
    reply = client.post("/heal", json={"path": "CLAUDE.md"}, headers=headers).json()
    assert reply["receipt"] == [
        "heal_apply: 2 fixed \u00b7 0 left for a decision \u00b7 0 put back",
        "CLAUDE.md  2 fixed",
    ]
    body = (project / "CLAUDE.md").read_text()
    assert "*linter*" in body and "`build.sh`" in body and body != DOC


@pytest.mark.requires_model
def test_heal_button_puts_back_a_file_that_departs(
    client: TestClient, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reporails_cli.core.heal.keyed as keyed

    original_apply = keyed.apply_edits

    def touching_neighbour(lines: Any, edits: Any) -> Any:
        body, where = original_apply(lines, edits)
        body[0] += " extra"
        return body, where

    monkeypatch.setattr(keyed, "apply_edits", touching_neighbour)
    _real_heal(project, monkeypatch)
    headers = {"X-Xray-Token": TOKEN, "Origin": ORIGIN}
    reply = client.post("/heal", json={"path": "CLAUDE.md"}, headers=headers).json()
    assert reply["receipt"][0] == "heal_apply: 0 fixed \u00b7 0 left for a decision \u00b7 1 put back"
    assert "put back: CLAUDE.md (outside  line 1)" in reply["receipt"]
    assert (project / "CLAUDE.md").read_bytes() == DOC.encode()


def test_view_carries_the_contract_keys_and_answers_the_same_version_with_304(client: TestClient) -> None:
    first = client.get("/view", headers={"X-Xray-Token": TOKEN})
    assert first.status_code == 200 and set(first.json()) == TOP_KEYS and first.json()["turns"]
    again = client.get("/view", headers={"X-Xray-Token": TOKEN, "If-None-Match": first.headers["ETag"]})
    assert again.status_code == 304


def test_the_page_carries_the_policy_and_the_token(client: TestClient) -> None:
    reply = client.get("/")
    assert "default-src 'self'" in reply.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in reply.headers["Content-Security-Policy"]
    assert reply.headers["Cache-Control"] == "no-store"
    assert "__XRAY_TOKEN__" not in reply.text and f'content="{TOKEN}"' in reply.text


def test_the_page_and_its_data_load_with_the_network_blocked(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise OSError("network blocked")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    paths = ["/", "/view", "/xray.js", "/xray.css", "/fonts/Geist-Variable.woff2", "/fonts/GeistMono-Variable.woff2"]
    codes = [client.get(path, headers={"X-Xray-Token": TOKEN}).status_code for path in paths]
    assert codes == [200] * len(paths)


def test_the_server_binds_the_loopback_address_only() -> None:
    sock = xray_server.bound_socket()
    try:
        assert sock.getsockname()[0] == "127.0.0.1" and sock.getsockname()[1] > 0
    finally:
        sock.close()


def test_xray_help_loads_no_server_or_ml_runtime(tmp_path: Path) -> None:
    script = (
        "import json, sys\n"
        "from reporails_cli.interfaces.cli import entry\n"
        "sys.argv = ['ails', 'xray', '--help']\n"
        "try:\n    entry.run()\nexcept SystemExit:\n    pass\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=60,
        env={"HOME": str(tmp_path), "USERPROFILE": str(tmp_path), "PATH": ""},
        check=False,
    )
    loaded = set(json.loads(done.stdout.splitlines()[-1]))
    present = [m for m in HEAVY if m in loaded or any(name.startswith(m + ".") for name in loaded)]
    assert present == [], present
