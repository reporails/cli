"""Step definitions for the x-ray demonstrations: the real `ails xray` binary and its page over HTTP."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from behave import given, then, when  # type: ignore[import-untyped]
from support import AILS_BIN, build_project, run_ails  # behave puts features/ on sys.path

from reporails_cli.bundled import get_xray_path
from reporails_cli.core.discovery.agent_discovery import claude_project_folder_name
from tests.suite_env import suite_env

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript" / "2.1.308"
STARTUP_LIMIT_S = 60


def _start(context) -> None:
    assert AILS_BIN is not None, "`ails` console script not on PATH (run via `uv run behave`)"
    env = {**suite_env(os.environ), "HOME": str(context.home), "USERPROFILE": str(context.home)}
    proc = subprocess.Popen(  # pylint: disable=consider-using-with  # stopped by the scenario cleanup
        [str(AILS_BIN), "xray", "--no-open"],
        cwd=str(context.project),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    context.add_cleanup(proc.kill)
    watchdog = threading.Timer(STARTUP_LIMIT_S, proc.kill)
    watchdog.start()
    context.add_cleanup(watchdog.cancel)
    context.xray_line = proc.stdout.readline()


@given("a project with a recorded Claude Code session")
def step_project_with_session(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    folder = context.home / ".claude" / "projects" / claude_project_folder_name(context.project)
    folder.mkdir(parents=True)
    shutil.copytree(FIXTURE / "session", folder / "session")
    text = (FIXTURE / "session.jsonl").read_text(encoding="utf-8").replace("/work/proj", str(context.project))
    (folder / "session.jsonl").write_text(text, encoding="utf-8")


@given("a project with a recorded Claude Code session that compacted twice")
def step_project_with_compactions(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    folder = context.home / ".claude" / "projects" / claude_project_folder_name(context.project)
    folder.mkdir(parents=True)
    source = FIXTURE.parent / "2.1.309-compactions" / "session.jsonl"
    (folder / "session.jsonl").write_text(
        source.read_text(encoding="utf-8").replace("/work/proj", str(context.project)), encoding="utf-8"
    )


@given('the project\'s instruction file reads "{text}"')
def step_instruction_text(context, text):
    (context.project / "CLAUDE.md").write_text(text + "\n", encoding="utf-8")


@given('the project\'s memory folder holds an unlinked topic file reading "{text}"')
def step_unlinked_memory(context, text):
    memory = context.home / ".claude" / "projects" / claude_project_folder_name(context.project) / "memory"
    memory.mkdir()
    (memory / "MEMORY.md").write_text("# Memory\n", encoding="utf-8")
    (memory / "feedback_orphan.md").write_text(f"---\ntype: feedback\n---\n{text}\n", encoding="utf-8")


@given('the project\'s memory folder holds an unlinked note named "{name}" reading "{text}"')
def step_unlinked_named_memory(context, name, text):
    memory = context.home / ".claude" / "projects" / claude_project_folder_name(context.project) / "memory"
    memory.mkdir()
    (memory / "MEMORY.md").write_text("# Memory\n", encoding="utf-8")
    (memory / name).write_text(f"---\ntype: feedback\n---\n{text}\n", encoding="utf-8")


@given('the session\'s first prompt was typed and reads "{text}"')
def step_typed_prompt(context, text):
    session = next((context.home / ".claude" / "projects").rglob("session.jsonl"))
    rows = [json.loads(row) for row in session.read_text(encoding="utf-8").splitlines()]
    first = rows[0]
    first["uuid"] = "typed-prompt-1"
    first["promptSource"] = "typed"
    first["origin"] = {"kind": "human"}
    first["message"]["content"] = text
    session.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


@given("a project with no recorded Claude Code session")
def step_project_without_session(context):
    context.project = build_project(context.tmpdir / "proj").resolve()


@when('"ails xray --no-open" is started in the project')
def step_start(context):
    _start(context)


@when('"ails xray --no-open" is run in the project')
def step_run(context):
    context.result = run_ails(context.project, "xray", "--no-open", home=context.home, timeout=60)


@then("the printed address is on 127.0.0.1")
def step_address(context):
    found = re.search(r"http://127\.0\.0\.1:\d+/", context.xray_line)
    assert found, f"no loopback address printed: {context.xray_line!r}"
    context.url = found.group(0)


def _get(url: str, token: str | None = None) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"X-Xray-Token": token} if token else {})
    try:
        with urllib.request.urlopen(request, timeout=30) as reply:
            return reply.status, reply.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, ""


@then("the page carries a launch token and the session view with that token holds the main agent")
def step_view(context):
    status, page = _get(context.url)
    assert status == 200
    token = re.search(r'name="xray-token" content="([^"]+)"', page)
    assert token and token.group(1) != "__XRAY_TOKEN__", "the page carries no launch token"
    status, body = _get(context.url + "view", token.group(1))
    assert status == 200, status
    assert [node["id"] for node in json.loads(body)["nodes"]][:1] == ["main"]


def _layout_script(context, mode: str, *args: str) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    script = Path(__file__).resolve().parents[1] / "xray_layout.mjs"
    done = subprocess.run(
        [node, str(script), context.url, mode, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


@then('opening the not-loaded memory file shows "{text}"')
def step_memory_selected(context, text):
    seen = _layout_script(context, "memory")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    sources = json.loads(_get(context.url + "view", token)[1])["sources"]
    names = [s["name"] for s in sources if s["path"].endswith("feedback_orphan.md")]
    assert names and seen["row"] == names[0], (names, seen)
    assert text in seen["text"], seen


@then("checking the instruction file lists each finding with the message the check route returns")
def step_finding_messages(context):
    seen = _layout_script(context, "check")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    request = urllib.request.Request(
        context.url + "check",
        data=json.dumps({"path": "CLAUDE.md"}).encode(),
        headers={"x-xray-token": token, "Origin": context.url.rstrip("/"), "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as reply:
        lines = json.loads(reply.read())["lines"]
    assert lines and len(seen["rows"]) == len(lines), (seen["rows"], lines)
    for row, line in zip(seen["rows"], lines, strict=True):
        assert line["message"] in row, (row, line)


@then("the prompt line shows no text and asks for none until it is clicked, then shows what the prompt route returns")
def step_prompt_on_click(context):
    seen = _layout_script(context, "prompt")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    assert seen["before"] == "0 0", seen
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    status, body = _get(context.url + "prompt?id=" + seen["id"], token)
    assert status == 200, status
    assert seen["text"] == json.loads(body)["text"] == "typed prompt text", (seen, body)


@then("the markup in the file name, the file and the prompt shows literally and no element or handler was injected")
def step_markup_is_text(context):
    seen = _layout_script(context, "markup")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    assert seen["row"] == "<img src=x onerror=window.__pwned=1>", seen
    assert seen["text"].strip().endswith("<b>bold</b>"), seen
    assert seen["promptText"] == "<b>bold</b> <img src=x onerror=window.__pwned=1>", seen
    assert seen["dom"] == {"pwned": None, "imgs": 0, "inPeek": 0, "rowChildren": 0}, seen


@then("the page's scripts write to no HTML sink")
def step_no_html_sink(context):
    scripts = sorted(get_xray_path().rglob("*.js"))
    assert scripts, "the page has no scripts"
    sinks = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|createContextualFragment|DOMParser")
    found = [
        f"{path.name}: {hit.group(0)}" for path in scripts for hit in sinks.finditer(path.read_text(encoding="utf-8"))
    ]
    assert not found, found


@then('the page shows "{first}" for the file, then "{second}" once the file and the session change')
def step_pane_follows_file(context, first, second):
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return
    script = Path(__file__).resolve().parents[1] / "xray_pane.mjs"
    proc = subprocess.Popen(  # pylint: disable=consider-using-with  # stopped by the scenario cleanup
        [node, str(script), context.url, "CLAUDE.md"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    context.add_cleanup(proc.kill)
    shown = proc.stdout.readline()
    assert first in shown, shown
    (context.project / "CLAUDE.md").write_text(second + "\n", encoding="utf-8")
    session = next((context.home / ".claude" / "projects").rglob("session.jsonl"))
    rows = session.read_text(encoding="utf-8").splitlines()
    later = json.loads(rows[-1])
    later["message"]["id"] = "msg_later"
    later["timestamp"] = "2026-10-30T20:11:39.626Z"
    session.write_text("\n".join([*rows, json.dumps(later)]) + "\n", encoding="utf-8")
    proc.stdin.write("go\n")
    proc.stdin.flush()
    after = proc.stdout.readline()
    assert second in after, after


@then("the session view without the token is refused with 403")
def step_no_token(context):
    assert _get(context.url + "view")[0] == 403


@then("it exits 2 saying no Claude Code session was found")
def step_refused(context):
    assert context.result.returncode == 2, context.result.returncode
    assert "no Claude Code session found" in context.result.stderr


@then("the page draws a compaction marker for each of the two compactions with the sizes the view holds")
def step_compaction_markers(context):
    seen = _layout_script(context, "compactions")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    token = re.search(r'name="xray-token" content="([^"]+)"', _get(context.url)[1]).group(1)
    stations = json.loads(_get(context.url + "view", token)[1])["stations"]
    held = next(station["compactions"] for station in stations if station["node"] == "main")
    assert len(held) == 2 and len(seen["markers"]) == 2, (held, seen)
    for marker, item in zip(seen["markers"], held, strict=True):
        assert marker.startswith("compacted"), marker
        if item["before"] is not None and item["after"] is not None:
            assert f"{_k1(item['before'])} → {_k1(item['after'])}" in marker, (marker, item)


def _k1(n: int) -> str:
    return f"{n / 1000:.0f}k" if n >= 10_000 else f"{n / 1000:.1f}".removesuffix(".0") + "k" if n >= 1000 else str(n)


# ---- the bundled page over a fixture view, served by a server this file owns ----

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "xray"
STUB_NODE = Path(__file__).resolve().parents[1] / "xray_stub_node.js"
TOKEN = "fixture-token"
TYPES = {".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2", ".html": "text/html"}
CALLS = {"toolu_fail0": "npm test -- --runInBand"}


class _FixtureHandler(BaseHTTPRequestHandler):
    """The routes the page calls: its own files from the bundle, a fixture `/view`, and canned text routes."""

    view_text = ""

    def log_message(self, *_args) -> None:  # silence the per-request log
        return

    def _send(self, status: int, body: bytes, kind: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def do_GET(self) -> None:  # http.server's name
        url = urlparse(self.path)
        query = parse_qs(url.query)
        root = get_xray_path()
        if url.path == "/":
            page = (root / "index.html").read_text(encoding="utf-8").replace("__XRAY_TOKEN__", TOKEN)
            return self._send(200, page.encode(), "text/html")
        if url.path.startswith("/static/"):
            target = (root / url.path.removeprefix("/static/")).resolve()
            if not target.is_file() or root.resolve() not in target.parents:
                return self._json(404, {"error": "no such file"})
            return self._send(200, target.read_bytes(), TYPES.get(target.suffix, "application/octet-stream"))
        if url.path == "/test/stub_node.js":
            return self._send(200, STUB_NODE.read_bytes(), "text/javascript")
        if self.headers.get("X-Xray-Token") != TOKEN:
            return self._json(403, {"error": "token"})
        if url.path == "/view":
            return self._send(200, self.view_text.encode(), "application/json")
        key = query.get("id", query.get("subagent", query.get("path", [""])))[0]
        texts = {
            "/call": CALLS.get(key, ""),
            "/brief": f"task text of {key}",
            "/prompt": f"prompt text of {key}",
            "/peek": f"text of {key}",
        }
        if url.path in texts:
            return self._json(200, {"id": key, "text": texts[url.path]})
        return self._json(404, {"error": "no such route"})

    def do_POST(self) -> None:  # http.server's name
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        lines = [
            {
                "line": 3,
                "rule": "CORE:S:0001",
                "message": "fixture finding",
                "severity": "warning",
                "title": "t",
                "category": "c",
                "file_level": False,
                "docs_url": None,
            }
        ]
        self._json(200, {"lines": lines})


@given('the bundled page is served over the "{name}" fixture view')
def step_serve_fixture(context, name):
    text = (FIXTURES / f"{name}.json").read_text(encoding="utf-8")
    handler = type("Handler", (_FixtureHandler,), {"view_text": text})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    context.add_cleanup(server.shutdown)
    context.add_cleanup(server.server_close)
    context.url = f"http://127.0.0.1:{server.server_address[1]}/"
    context.fixture = json.loads(text)


def _page(context, mode: str, width: int = 1440) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    done = subprocess.run(
        [node, str(Path(__file__).resolve().parents[1] / "xray_page.mjs"), context.url, mode, str(width)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout.strip().splitlines()[-1])
    assert seen["ready"], f"the page did not draw the fixture in mode {mode}"
    return seen


@then("no two cards overlap at 1440 and at 925 pixels, and the subagents stacked in time say how many more run")
def step_no_card_overlap(context):
    for width in (1440, 925):
        seen = _page(context, "overlap", width)
        if seen is None:
            return
        assert seen["cards"] == len(context.fixture["nodes"][0]["children"]) + 1, (width, seen)  # top node + subagents
        assert seen["overlaps"] == 0, (width, seen)
    assert any(text.endswith("running") and text.startswith("+") for text in seen["running"]), seen


@then("drilling in three levels shows the collapsed breadcrumb and the parent strip of the direct parent")
def step_drill_in(context):
    seen = _page(context, "drill")
    if seen is None:
        return
    assert seen["crumbs"] == ["main agent", "/", "…", "/", "Fetch the spec"], seen
    assert seen["strip"] and seen["parent"] == "Survey the docs", seen
    assert seen["bars"] == ["a5c"] and seen["current"] == ["a5c"], seen
    assert seen["rootStrip"] is True, seen


@then("focusing a source rings exactly the nodes that had it and dims the rest, and a never-loaded source says so")
def step_focus_source(context):
    seen = _page(context, "focus")
    if seen is None:
        return
    nodes = {node["id"]: node for node in context.fixture["nodes"]}
    had = set(next(s for s in context.fixture["sources"] if s["id"] == "mcp:docs-server")["had_by"])
    here = list(nodes["main"]["children"])
    assert {c["id"] for c in seen["mcp"] if c["ring"]} == had & set(here), seen["mcp"]
    assert {c["id"] for c in seen["mcp"] if c["dim"]} == set(here) - had, seen["mcp"]
    assert seen["mcpTop"] is ("main" in had), seen
    assert all(c["dim"] and not c["ring"] for c in seen["never"]), seen["never"]
    assert "Never loaded by any agent in this session." in seen["neverBanner"], seen
    assert seen["neverRow"] is True, seen


@then("toggling a layer removes that kind's slot chips, Sources section and stations at once")
def step_toggle_layer(context):
    seen = _page(context, "layer")
    if seen is None:
        return
    assert all(seen["before"][key] > 0 for key in ("chips", "sections", "stations", "other")), seen
    assert seen["after"]["chips"] == seen["after"]["sections"] == seen["after"]["stations"] == 0, seen
    assert seen["after"]["other"] == seen["before"]["other"], seen
    assert seen["again"] == seen["before"], seen


@then("the page draws no slot, toggle, section or station for a source kind the adapter omits")
def step_omitted_kinds(context):
    seen = _page(context, "omitted")
    if seen is None:
        return
    kept = [kind["key"] for kind in context.fixture["adapter"]["source_kinds"]]
    assert set(kept) == {"instructions", "memory", "skill"}, kept
    assert set(seen["toggles"]) == set(kept), seen
    assert set(seen["sections"]) <= set(kept) and set(seen["chips"]) <= set(kept), seen
    omitted = ("mcp:", ".claude/rules", "hook:")
    assert not [s for s in seen["stations"] if s.startswith(omitted)], seen
    assert seen["empty"] == 0 and "Stub Agent" in seen["adapter"], seen


@then("a compaction marker, a stopped subagent and a never-loaded source each render as specified")
def step_special_marks(context):
    seen = _page(context, "markers")
    if seen is None:
        return
    assert len(seen["compact"]) == 1 and seen["compact"][0].startswith("compacted · 529k → 53k"), seen["compact"]
    never = " ".join(seen["never"])
    assert "packages/cli/CLAUDE.md | on disk, never loaded" in never, seen["never"]
    assert any(row.endswith("listed, never loaded") for row in seen["never"]), seen["never"]
    stopped = seen["stopped"]
    assert stopped["dashed"] and stopped["up"] == 0 and stopped["down"] == 1, stopped
    assert "stopped" in stopped["inspector"] and "Came back" not in stopped["inspector"], stopped
    assert stopped["animated"] == 1, stopped  # the out arch only: a stopped return never animates
    assert seen["returned"] == {"up": 1, "down": 1, "animated": 2}, seen["returned"]
    assert seen["reduced"] == "none", seen["reduced"]
    assert seen["bracket"].startswith("npm test -- --runInBand \u00d79"), seen["bracket"]


@then("a findings pill opens the file's findings at its hash and a source row links to its file")
def step_open_file(context):
    seen = _page(context, "file")
    if seen is None:
        return
    assert seen["pill"] == seen["hash"] == "#/file/CLAUDE.md", seen
    assert seen["name"] == "CLAUDE.md" and seen["peek"] == "text of CLAUDE.md", seen
    assert seen["backHash"].startswith("#/agent/main"), seen
    assert seen["row"] == "#/file/.claude/rules/rules-engine.md", seen


@then("the stub kind's cards are drawn by a stub renderer only the test serves, with no change to the canvas")
def step_stub_kind(context):
    seen = _page(context, "stub")
    if seen is None:
        return
    assert "stub" in seen["before"].lower() and "STUB" not in seen["before"], seen
    assert seen["after"] == "STUB Stub worker", seen
    assert seen["inspector"] == "stub inspector for stub1", seen
    assert seen["agentCard"] == 1, seen  # the agent kind still draws its own top node
