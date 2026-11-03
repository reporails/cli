"""The x-ray page server: every guard refuses before a core call, the routes translate, the page loads offline."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.testclient import TestClient

from reporails_cli.core.discovery.agent_discovery import claude_project_dir
from reporails_cli.core.pipeline.mapping import map_instruction_files
from reporails_cli.core.platform.adapters.rules_query import rule_category, rule_title
from reporails_cli.core.platform.adapters.workflow_wire import deserialize_workflow
from reporails_cli.core.platform.dto.diagnostics import FindingItem
from reporails_cli.core.platform.dto.heal import HealOutcome, KeyedResult
from reporails_cli.core.platform.dto.pipeline import Refusal
from reporails_cli.formatters.text.rule_meta import rule_docs_url
from reporails_cli.interfaces.cli import xray_server
from tests.unit.test_mcp_heal_apply import DOC, _wire

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript" / "2.1.308"
TOKEN = "launch-token"
LAUNCH = "launch-id"
PORT = 8765
ORIGIN = f"http://127.0.0.1:{PORT}"
TOP_KEYS = {
    "version", "session", "project", "started_at", "length_s", "picked", "model", "window", "adapter", "price_list",
    "nodes", "edges", "sources", "stations", "track", "funnel", "facts", "check", "refusals", "not_known",
}  # fmt: skip
HEAVY = ("starlette", "uvicorn", "reporails_cli.core.mapper", "onnxruntime", "tokenizers", "numpy")


class Calls:
    """What the fake core was asked."""

    def __init__(self) -> None:
        self.checked: list[str] = []
        self.healed: list[str] = []
        self.roots: list[Path] = []


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

    def fake_check(path: str, root: Path) -> Refusal:
        seen.checked.append(path)
        seen.roots.append(root)
        return Refusal("failed", "fake refusal")

    def fake_heal(path: str, root: Path) -> HealOutcome:
        seen.healed.append(path)
        seen.roots.append(root)
        return HealOutcome(KeyedResult(), "", Path(path).parent)

    monkeypatch.setattr(xray_server, "check_path", fake_check)
    monkeypatch.setattr(xray_server, "heal_one", fake_heal)
    return seen


@pytest.fixture
def client(project: Path, tmp_path: Path) -> TestClient:
    app = xray_server.build_app(
        project,
        tmp_path / "session" / "session.jsonl",
        picked="newest",
        token=TOKEN,
        launch=LAUNCH,
        port=PORT,
        requests=xray_server.RequestClock(),
    )
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


@pytest.mark.parametrize("route", ["/check", "/heal"])
def test_a_project_file_the_page_does_not_list_is_refused_before_the_core(
    client: TestClient, project: Path, calls: Calls, route: str
) -> None:
    (project / "notes.txt").write_text("notes\n")
    reply = client.post(route, json={"path": "notes.txt"}, headers={"X-Xray-Token": TOKEN, "Origin": ORIGIN})
    assert reply.status_code == 400 and reply.json() == {"error": "not a file this page lists"}
    assert calls.checked == [] and calls.healed == []


def test_check_and_heal_read_the_project_the_server_was_opened_on(
    client: TestClient, project: Path, calls: Calls
) -> None:
    headers = {"X-Xray-Token": TOKEN, "Origin": ORIGIN}
    client.post("/check", json={"path": "CLAUDE.md"}, headers=headers)
    client.post("/heal", json={"path": "CLAUDE.md"}, headers=headers)
    assert calls.roots == [project, project]


def test_check_reports_a_refusal_as_400_and_a_file_as_its_findings(
    client: TestClient, project: Path, calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    reply = client.post("/check", json={"path": "CLAUDE.md"}, headers={"X-Xray-Token": TOKEN, "Origin": ORIGIN})
    assert reply.status_code == 400 and reply.json() == {"error": "fake refusal"}
    assert calls.checked == [str((project / "CLAUDE.md").resolve())]

    class Run:
        pass

    finding = FindingItem(file="CLAUDE.md", line=3, severity="warning", rule="CORE:C:0053", message="Say it plainly")
    monkeypatch.setattr(xray_server, "check_path", lambda path, root: Run())
    monkeypatch.setattr(xray_server, "file_findings", lambda run, file: (finding,))
    reply = client.post("/check", json={"path": "CLAUDE.md"}, headers={"X-Xray-Token": TOKEN, "Origin": ORIGIN})
    assert reply.json()["findings"] == 1
    assert reply.json()["fix_command"] == "ails check CLAUDE.md --heal"
    [line] = reply.json()["lines"]
    assert set(line) == {"line", "rule", "message", "severity", "title", "category", "file_level", "docs_url"}
    assert (line["line"], line["rule"], line["severity"], line["file_level"]) == (3, "CORE:C:0053", "warning", False)
    assert line["title"] == rule_title("CORE:C:0053") != ""
    assert line["category"] == rule_category("CORE:C:0053") != ""
    assert line["docs_url"] == rule_docs_url("CORE:C:0053") is not None
    view = client.get("/view", headers={"X-Xray-Token": TOKEN}).json()
    artifact = next(a for a in view["sources"] if a["path"].endswith("CLAUDE.md"))
    assert artifact["findings"] == {"count": 1, "by_severity": {"error": 0, "warning": 1, "info": 0}}


def _view_of(client: TestClient) -> Any:
    return client.get("/view", headers={"X-Xray-Token": TOKEN}).json()


def _settled_view(client: TestClient) -> Any:
    for _ in range(100):
        view = _view_of(client)
        if view["check"]["state"] != "running":
            return view
        time.sleep(0.05)
    raise AssertionError("the launch check never landed")


def test_the_launch_check_fills_every_files_tally_and_moves_the_version(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = FindingItem(file="CLAUDE.md", line=1, severity="error", rule="CORE:C:0053", message="m")
    other = FindingItem(file="CLAUDE.md", line=4, severity="info", rule="CORE:C:0053", message="m")
    run = SimpleNamespace(
        result=SimpleNamespace(findings=[finding, other]),
        scope=SimpleNamespace(scan_root=project.resolve(), instruction_files=[project / "CLAUDE.md"]),
    )
    monkeypatch.setattr(xray_server, "check_path", lambda path, root: run)
    app = xray_server.build_app(
        project,
        tmp_path / "session" / "session.jsonl",
        picked="newest",
        token=TOKEN,
        launch=LAUNCH,
        port=PORT,
        requests=xray_server.RequestClock(),
    )
    with TestClient(app, base_url=ORIGIN) as client:
        view = _settled_view(client)
        artifact = next(a for a in view["sources"] if a["path"].endswith("CLAUDE.md"))
        assert view["check"] == {"state": "done", "message": None}
        assert artifact["findings"] == {"count": 2, "by_severity": {"error": 1, "warning": 0, "info": 1}}


def test_the_view_says_running_until_the_launch_check_lands_and_the_version_moves_when_it_does(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()

    def slow_check(path: str, root: Path) -> Refusal:
        release.wait(5)
        return Refusal("failed", "no model")

    monkeypatch.setattr(xray_server, "check_path", slow_check)
    app = xray_server.build_app(
        project,
        tmp_path / "session" / "session.jsonl",
        picked="newest",
        token=TOKEN,
        launch=LAUNCH,
        port=PORT,
        requests=xray_server.RequestClock(),
    )
    with TestClient(app, base_url=ORIGIN) as client:
        first = _view_of(client)
        assert first["check"] == {"state": "running", "message": None}
        release.set()
        view = _settled_view(client)
        assert view["check"] == {"state": "refused", "message": "no model"}
        assert view["version"] > first["version"]


def test_heal_replies_with_the_receipt_or_the_reason_nothing_was_written(
    client: TestClient, calls: Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = {"X-Xray-Token": TOKEN, "Origin": ORIGIN}
    reply = client.post("/heal", json={"path": "CLAUDE.md"}, headers=headers).json()
    assert reply["receipt"][0].startswith("heal_apply: 0 fixed")
    monkeypatch.setattr(
        xray_server, "heal_one", lambda path, root: HealOutcome(None, "Applying fixes needs a Pro account.", Path())
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
    monkeypatch.setattr("reporails_cli.core.heal.apply.check_path", lambda _path, _root: run)


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
    assert first.status_code == 200 and set(first.json()) == TOP_KEYS and first.json()["nodes"]
    again = client.get("/view", headers={"X-Xray-Token": TOKEN, "If-None-Match": first.headers["ETag"]})
    assert again.status_code == 304


def test_view_lists_no_plugin_file_and_shows_the_refusal_when_the_install_record_is_malformed(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", str(tmp_path / "plugins"))
    (tmp_path / "plugins").mkdir()
    (tmp_path / "plugins" / "installed_plugins.json").write_text("{not json")
    reply = client.get("/view", headers={"X-Xray-Token": TOKEN})
    body = reply.json()
    assert reply.status_code == 200
    assert any("installed_plugins.json" in refusal for refusal in body["refusals"])
    # Only the files the session loaded and the project lists are sources: no plugin file is among them.
    paths = [a["path"] for a in body["sources"]]
    assert "CLAUDE.md" in paths and not any("plugins" in path for path in paths)


def test_the_page_carries_the_policy_and_the_token(client: TestClient) -> None:
    reply = client.get("/")
    assert "default-src 'self'" in reply.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in reply.headers["Content-Security-Policy"]
    assert reply.headers["Cache-Control"] == "no-store"
    assert "__XRAY_TOKEN__" not in reply.text and f'content="{TOKEN}"' in reply.text


def test_module_scripts_are_served_as_javascript_from_the_one_static_mount(client: TestClient) -> None:
    reply = client.get("/static/js/components/canvas.js")
    assert reply.status_code == 200
    assert reply.headers["content-type"].split(";")[0] == "text/javascript"
    page = client.get("/").text
    assert '<script type="module" src="/static/js/main.js"></script>' in page
    assert "/static/xray.css" in page


def test_the_per_file_page_routes_are_gone(client: TestClient) -> None:
    for path in ["/xray.js", "/xray.css", "/fonts/Geist-Variable.woff2", "/static/xray.js"]:
        assert client.get(path).status_code == 404


def test_the_page_and_its_data_load_with_the_network_blocked(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise OSError("network blocked")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    paths = [
        "/",
        "/view",
        "/static/js/main.js",
        "/static/xray.css",
        "/static/fonts/InterVariable.woff2",
        "/static/fonts/JetBrainsMono-Variable.woff2",
    ]
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


SUB_ID = "a27081343121455fb"


def _get(client: TestClient, route: str, query: dict[str, str], token: str | None = TOKEN) -> Any:
    headers = {} if token is None else {"X-Xray-Token": token}
    return client.get(route, params=query, headers=headers)


def test_peek_replies_with_the_text_of_a_listed_file(client: TestClient, project: Path) -> None:
    reply = _get(client, "/peek", {"path": "CLAUDE.md"})
    assert reply.status_code == 200 and reply.headers["Cache-Control"] == "no-store"
    assert reply.json() == {"path": "CLAUDE.md", "text": (project / "CLAUDE.md").read_text(), "truncated": False}


def test_peek_reads_a_listed_memory_file_by_its_home_path(
    client: TestClient, project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    memory = claude_project_dir(project) / "memory" / "MEMORY.md"
    memory.parent.mkdir(parents=True)
    memory.write_text("# Memory\n")
    shown = [a["path"] for a in client.get("/view", headers={"X-Xray-Token": TOKEN}).json()["sources"]]
    path = next(item for item in shown if item.endswith("MEMORY.md"))
    assert path.startswith("~/")
    assert _get(client, "/peek", {"path": path}).json()["text"] == "# Memory\n"


def test_peek_refuses_an_unlisted_path_a_hook_config_and_a_missing_query(client: TestClient, project: Path) -> None:
    (project / "notes.txt").write_text("notes\n")
    (project / ".claude").mkdir()
    (project / ".claude" / "settings.json").write_text('{"hooks": {"Stop": []}}')
    for path in ["notes.txt", ".claude/settings.json", "../outside.md", "/etc/passwd"]:
        reply = _get(client, "/peek", {"path": path})
        assert reply.status_code == 400 and reply.json() == {"error": "not a file this page lists"}
    assert _get(client, "/peek", {}).status_code == 400


def test_peek_and_brief_without_the_launch_token_are_refused(client: TestClient) -> None:
    assert _get(client, "/peek", {"path": "CLAUDE.md"}, token=None).status_code == 403
    assert _get(client, "/peek", {"path": "CLAUDE.md"}, token="wrong").status_code == 403
    assert _get(client, "/brief", {"subagent": SUB_ID}, token=None).status_code == 403


def test_brief_replies_with_the_text_a_listed_subagent_was_given(client: TestClient) -> None:
    client.get("/view", headers={"X-Xray-Token": TOKEN})
    reply = _get(client, "/brief", {"subagent": SUB_ID})
    assert reply.status_code == 200 and reply.headers["Cache-Control"] == "no-store"
    assert reply.json() == {"id": SUB_ID, "text": "PLACEHOLDER_PROMPT_TEXT"}


def test_brief_refuses_an_unknown_subagent_and_a_missing_query(client: TestClient) -> None:
    reply = _get(client, "/brief", {"subagent": "nosuchagent"})
    assert reply.status_code == 400 and reply.json() == {"error": "not a subagent this page lists"}
    assert _get(client, "/brief", {}).status_code == 400


def test_view_still_carries_no_text(client: TestClient) -> None:
    body = client.get("/view", headers={"X-Xray-Token": TOKEN}).text
    # A subagent's task description names its node; no prompt, tool or file text is in the view.
    assert "PLACEHOLDER" not in body.replace("PLACEHOLDER_DESCRIPTION", "")


def test_brief_replies_with_the_refusal_when_the_subagent_file_opens_with_no_user_row(
    client: TestClient, tmp_path: Path
) -> None:
    file = tmp_path / "session" / "session" / "subagents" / f"agent-{SUB_ID}.jsonl"
    rows = [json.loads(line) for line in file.read_text().splitlines()]
    rows[0]["type"] = "assistant"
    file.write_text("".join(json.dumps(row) + "\n" for row in rows))
    client.get("/view", headers={"X-Xray-Token": TOKEN})
    reply = _get(client, "/brief", {"subagent": SUB_ID})
    assert reply.status_code == 400 and "user row" in reply.json()["error"]


@pytest.fixture
def prompt_client(project: Path, tmp_path: Path) -> TestClient:
    copy = tmp_path / "prompts"
    shutil.copytree(FIXTURES.parent / "2.1.309-turns", copy)
    app = xray_server.build_app(
        project,
        copy / "session.jsonl",
        picked="newest",
        token=TOKEN,
        launch=LAUNCH,
        port=PORT,
        requests=xray_server.RequestClock(),
    )
    return TestClient(app, base_url=ORIGIN)


def test_prompt_replies_with_the_text_of_a_prompt_the_view_lists_and_is_never_cached(
    prompt_client: TestClient,
) -> None:
    view = prompt_client.get("/view", headers={"X-Xray-Token": TOKEN}).json()
    ids = [prompt["id"] for node in view["nodes"] for prompt in node["detail"]["prompts"]]
    assert ids == ["p-one", "p-two", "q-one"]
    reply = _get(prompt_client, "/prompt", {"id": "p-one"})
    assert reply.status_code == 200 and reply.headers["Cache-Control"] == "no-store"
    assert reply.json() == {"id": "p-one", "text": "PLACEHOLDER-TEXT-3"}


@pytest.mark.parametrize("prompt_id", ["t-result", "m-meta", "peer", "nosuchrow", "../x"])
def test_prompt_refuses_an_id_that_is_not_a_listed_prompt(prompt_client: TestClient, prompt_id: str) -> None:
    prompt_client.get("/view", headers={"X-Xray-Token": TOKEN})
    reply = _get(prompt_client, "/prompt", {"id": prompt_id})
    assert reply.status_code == 400 and reply.json() == {"error": "not a prompt this page lists"}
    assert _get(prompt_client, "/prompt", {}).status_code == 400


def test_prompt_without_the_launch_token_is_refused(prompt_client: TestClient) -> None:
    assert _get(prompt_client, "/prompt", {"id": "p-one"}, token=None).status_code == 403
    assert _get(prompt_client, "/prompt", {"id": "p-one"}, token="wrong").status_code == 403


def _server(project: Path, tmp_path: Path) -> xray_server.XrayServer:
    return xray_server.XrayServer(
        project.resolve(),
        tmp_path / "session" / "session.jsonl",
        picked="newest",
        token=TOKEN,
        launch=LAUNCH,
        port=PORT,
    )


def test_a_launch_check_that_fails_unexpectedly_lands_as_refused_with_the_error_text(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(path: str, root: Path) -> None:
        raise PermissionError("no read access")

    monkeypatch.setattr(xray_server, "check_path", boom)
    server = _server(project, tmp_path)
    with caplog.at_level("WARNING", logger=xray_server.__name__):
        server.launch_check()
    launch = server._session_for("session")
    assert launch is not None
    check = server._build_view(launch, "newest")[0]["check"]
    assert check == {"state": "refused", "message": "no read access"}
    assert any("no read access" in record.getMessage() for record in caplog.records)


def test_a_heal_ordered_after_the_launch_check_keeps_its_dropped_tally(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = SimpleNamespace(
        result=SimpleNamespace(findings=[]),
        scope=SimpleNamespace(scan_root=project.resolve(), instruction_files=[project / "CLAUDE.md"]),
    )
    monkeypatch.setattr(xray_server, "check_path", lambda path, root: run)
    monkeypatch.setattr(xray_server, "heal_one", lambda path, root: HealOutcome(KeyedResult(), "", project))
    server = _server(project, tmp_path)
    tallies_of = xray_server.tallies_by_file
    healers: list[threading.Thread] = []

    def tallies_with_a_heal_arriving(checked: Any) -> Any:
        # A heal arrives as the launch check turns its run into tallies, and gets as far as the lock lets it.
        healer = threading.Thread(target=server._heal, args=(project.resolve() / "CLAUDE.md",))
        healers.append(healer)
        healer.start()
        healer.join(0.3)
        return tallies_of(checked)

    monkeypatch.setattr(xray_server, "tallies_by_file", tallies_with_a_heal_arriving)
    server.launch_check()
    healers[0].join(5)
    assert "CLAUDE.md" not in server._findings


def test_file_level_is_the_whole_file_sentinel_line_zero_never_line_one() -> None:
    one = FindingItem(file="CLAUDE.md", line=1, severity="info", rule="CORE:C:0053", message="m", check_id="x")
    zero = FindingItem(file="CLAUDE.md", line=0, severity="info", rule="CORE:C:0053", message="m", check_id="x")
    assert xray_server._line(one)["file_level"] is False
    assert xray_server._line(zero)["file_level"] is True


@pytest.fixture
def handoff_client(project: Path, tmp_path: Path) -> TestClient:
    copy = tmp_path / "handoffs"
    shutil.copytree(FIXTURES.parent / "2.1.309-handoffs", copy)
    app = xray_server.build_app(
        project,
        copy / "session.jsonl",
        picked="newest",
        token=TOKEN,
        launch=LAUNCH,
        port=PORT,
        requests=xray_server.RequestClock(),
    )
    client = TestClient(app, base_url=ORIGIN)
    client.get("/view", headers={"X-Xray-Token": TOKEN})
    return client


def test_call_replies_with_the_command_of_a_main_and_a_subagent_shell_call_and_is_never_cached(
    handoff_client: TestClient,
) -> None:
    reply = _get(handoff_client, "/call", {"id": "toolu_bash1"})
    assert reply.status_code == 200 and reply.headers["Cache-Control"] == "no-store"
    assert reply.json() == {
        "id": "toolu_bash1",
        "tool": "Bash",
        "text": "PLACEHOLDER-COMMAND --flag",
        "input": reply.json()["input"],
        "result": "Exit code 1\nPLACEHOLDER-ERROR",
        "truncated": False,
    }
    assert _get(handoff_client, "/call", {"id": "toolu_bashD"}).json()["text"] == "PLACEHOLDER-SUB-COMMAND"


def test_call_replies_with_the_input_and_result_of_a_call_that_is_not_a_shell_one(handoff_client: TestClient) -> None:
    body = _get(handoff_client, "/call", {"id": "toolu_read1"}).json()
    assert (body["tool"], body["text"], body["truncated"]) == ("Read", None, False)
    assert json.loads(body["input"]) == {"file_path": "/work/proj/CLAUDE.md"}
    assert body["result"] == "PLACEHOLDER-FILE-TEXT" * 10


@pytest.mark.parametrize("call_id", ["toolu_nosuch", "../x"])
def test_call_refuses_an_id_that_is_not_a_call_of_the_session(handoff_client: TestClient, call_id: str) -> None:
    reply = _get(handoff_client, "/call", {"id": call_id})
    assert reply.status_code == 400 and reply.json() == {"error": "not a call this page lists"}
    assert _get(handoff_client, "/call", {}).status_code == 400


def test_call_without_the_launch_token_is_refused(handoff_client: TestClient) -> None:
    assert _get(handoff_client, "/call", {"id": "toolu_bash1"}, token=None).status_code == 403
    assert _get(handoff_client, "/call", {"id": "toolu_bash1"}, token="wrong").status_code == 403


TYPED_PROMPT = {
    "type": "user",
    "uuid": "u-1",
    "timestamp": "2026-10-30T20:10:30.000Z",
    "sessionId": "older",
    "promptSource": "typed",
    "origin": {"kind": "human"},
    "message": {"role": "user", "content": "open the settings page"},
}


@pytest.fixture
def two_sessions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """A page opened on the newer of two recorded sessions of one project."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    root = tmp_path / "two"
    root.mkdir()
    older = claude_project_dir(root) / "older.jsonl"
    older.parent.mkdir(parents=True)
    older.write_text(json.dumps(TYPED_PROMPT) + "\n", encoding="utf-8")
    newer = claude_project_dir(root) / "newer.jsonl"
    shutil.copy(FIXTURES / "session.jsonl", newer)
    os.utime(older, (1_000_000, 1_000_000))
    app = xray_server.build_app(
        root,
        newer,
        picked="current_unknown",
        token=TOKEN,
        launch=LAUNCH,
        port=PORT,
        requests=xray_server.RequestClock(),
    )
    return TestClient(app, base_url=ORIGIN)


def test_view_serves_the_session_the_query_names_from_the_same_server(two_sessions: TestClient) -> None:
    launch = _get(two_sessions, "/view", {}).json()
    older = _get(two_sessions, "/view", {"session": "older"}).json()
    assert (launch["session"], launch["picked"]) == ("newer", "current_unknown")
    assert (older["session"], older["picked"]) == ("older", "named")
    assert _get(two_sessions, "/view", {"session": "older", "pick": "current_unknown"}).json()["picked"] == (
        "current_unknown"
    )


def test_the_etag_names_the_session_so_two_sessions_never_share_one(two_sessions: TestClient) -> None:
    newer = _get(two_sessions, "/view", {})
    older = _get(two_sessions, "/view", {"session": "older"})
    assert newer.headers["ETag"].startswith('"newer:') and older.headers["ETag"].startswith('"older:')


@pytest.mark.parametrize("session", ["nosuch", "../outside", "a/b"])
def test_a_session_that_is_not_one_of_the_project_is_refused_on_every_session_route(
    two_sessions: TestClient, session: str
) -> None:
    for route in ("/view", "/sessions", "/first-prompt", "/peek", "/prompt"):
        reply = _get(two_sessions, route, {"session": session, "path": "x", "id": "x"})
        assert reply.status_code == 400 and reply.json() == {"error": "not a session of this project"}, route


def test_a_pick_outside_the_vocabulary_is_refused(two_sessions: TestClient) -> None:
    assert _get(two_sessions, "/view", {"pick": "bogus"}).status_code == 400


def test_sessions_lists_each_session_with_its_facts_and_the_one_the_request_is_on(two_sessions: TestClient) -> None:
    body = _get(two_sessions, "/sessions", {"session": "older"}).json()
    assert body["session"] == "older"
    by_id = {entry["session"]: entry for entry in body["sessions"]}
    assert set(by_id) == {"older", "newer"}
    assert by_id["older"]["started_at"] == "2026-10-30T20:10:30.000Z" and by_id["older"]["subagents"] == 0
    assert _get(two_sessions, "/sessions", {}).json()["session"] == "newer"


def test_first_prompt_replies_with_the_text_of_the_named_session_and_never_caches_it(two_sessions: TestClient) -> None:
    reply = _get(two_sessions, "/first-prompt", {"session": "older"})
    assert reply.json() == {"id": "older", "text": "open the settings page"}
    assert reply.headers["Cache-Control"] == "no-store"


def test_launch_answers_its_id_without_the_token_and_sessions_does_not(two_sessions: TestClient) -> None:
    assert _get(two_sessions, "/launch", {}, token=None).json() == {"launch": LAUNCH}
    assert _get(two_sessions, "/sessions", {}, token=None).status_code == 403
    assert _get(two_sessions, "/first-prompt", {"session": "older"}, token=None).status_code == 403


def test_the_launch_pick_is_kept_only_for_a_request_that_names_no_session(project: Path, tmp_path: Path) -> None:
    app = xray_server.build_app(
        project,
        tmp_path / "session" / "session.jsonl",
        picked="current_unknown",
        token=TOKEN,
        launch=LAUNCH,
        port=PORT,
        requests=xray_server.RequestClock(),
    )
    client = TestClient(app, base_url=ORIGIN)

    def picked(query: str) -> str:
        return client.get(f"/view{query}", headers={"X-Xray-Token": TOKEN}).json()["picked"]

    assert picked("") == "current_unknown"
    assert picked("?session=session") == "named"
    assert picked("?session=session&pick=current") == "current"


def test_a_page_whose_record_cannot_be_written_still_serves_and_forgets_nothing(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    served: list[bool] = []
    forgotten: list[str] = []

    def refuse(*_: object) -> None:
        raise PermissionError("read-only")

    class FakeServer:
        def __init__(self, _config: object) -> None:
            pass

        def run(self, **_: object) -> None:
            served.append(True)

    monkeypatch.setattr(xray_server, "register_page", refuse)
    monkeypatch.setattr(xray_server, "forget_page", lambda *_: forgotten.append("x"))
    monkeypatch.setattr(xray_server.uvicorn, "Server", FakeServer)
    with caplog.at_level("WARNING"):
        xray_server.serve(project, tmp_path / "session" / "session.jsonl", "newest", open_page=False)
    assert served == [True] and forgotten == []
    assert any("will not be reused" in r.getMessage() for r in caplog.records)
