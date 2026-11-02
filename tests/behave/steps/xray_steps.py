"""Step definitions for the x-ray demonstrations: the real `ails xray` binary and its page over HTTP."""

from __future__ import annotations

import itertools
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
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
    bump_version = False
    requests: ClassVar[list[str]] = []
    views_served = 0

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
        type(self).requests.append(self.path)
        if url.path == "/view":
            type(self).views_served += 1
            body = self.view_text
            if self.bump_version:  # a session that keeps growing: every poll carries a new version
                body = json.dumps({**json.loads(body), "version": 1000 + self.views_served})
            return self._send(200, body.encode(), "application/json")
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
        posted = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        type(self).requests.append(f"POST {self.path} {posted.get('path', '')}")
        time.sleep(1.2)  # a check takes a moment, so a second file can be opened while it runs
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
    handler = type(
        "Handler",
        (_FixtureHandler,),
        {"view_text": text, "requests": [], "bump_version": getattr(context, "bump_version", False)},
    )
    context.handler = handler
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


@then('no two cards overlap at 1440 and at 925 pixels and no "+N running" text is drawn')
def step_no_card_overlap(context):
    for width in (1440, 925):
        seen = _page(context, "overlap", width)
        if seen is None:
            return
        assert seen["overlaps"] == 0, (width, seen)
        assert seen["running"] == 0, (width, seen)


@then("at 1440 and at 925 pixels no card overlaps another and every card sits 18 pixels above its launch on the spine")
def step_no_displaced_card(context):
    for width in (1440, 925):
        seen = _page(context, "p1layout", width)
        if seen is None:
            return
        assert seen["overlaps"] == 0, (width, seen)
        assert seen["running"] == 0, (width, seen)
        assert len(seen["launches"]) == 5, seen["launches"]  # two group cards and three lone cards
        for card in seen["launches"]:
            assert abs(card["top"] + 18 - card["launchY"]) < 0.6, (width, card)
            # the edge leaves the spine where the card is anchored
            assert abs(card["top"] + 18 - card["out"]) < 8, (width, card)


@then(
    "the bursts are collapsed group cards, a click expands one into rows of four members "
    "and a second click collapses it"
)
def step_group_toggle(context):
    seen = _page(context, "p1groups")
    if seen is None:
        return
    assert [g["key"] for g in seen["groupsBefore"]] == ["main:b1", "main:c1"], seen
    first = seen["groupsBefore"][0]
    assert "⇉ 6" in first["text"] and "in parallel" in first["text"] and "expand \u203a" in first["text"], first
    assert first["tiles"] == 6 and first["dashed"] == "dashed" and first["expanded"] == "false", first
    assert seen["membersBefore"] == [], seen
    members = seen["membersOpen"]
    assert len(members) == 6, seen
    tops = sorted({m["top"] for m in members})
    assert len(tops) == 2, members
    assert [sum(1 for m in members if m["top"] == t) for t in tops] == [4, 2], members
    assert len({m["left"] for m in members if m["top"] == tops[0]}) == 4, members
    assert "⇉ fan-out · 6 subagents in parallel · " in seen["head"], seen["head"]
    assert seen["box"] is True and seen["groupCardsOpen"] == ["main:c1"], seen
    assert seen["arches"] == 6, seen
    assert seen["membersAfter"] == [] and seen["groupCardsAfter"] == 2, seen


@then("selecting a member of a collapsed group shows its group expanded until the user collapses it")
def step_group_selected(context):
    seen = _page(context, "p1select")
    if seen is None:
        return
    assert seen["before"] == 0, seen
    assert seen["after"] == 3 and seen["selected"] == "c2", seen
    assert seen["collapsed"] == 0 and seen["groupCard"] == 1, seen


@then(
    "a stretched segment shows a violet bar with its tooltip and the note, and no two ticks sit closer than 18 pixels"
)
def step_stretch_marked(context):
    seen = _page(context, "p1stretch")
    if seen is None:
        return
    assert seen["bars"], seen
    for bar in seen["bars"]:
        assert re.fullmatch(r"Scale stretched \d+\.\d\u00d7 between \d+:\d\d and \d+:\d\d", bar["title"]), bar
        assert bar["width"] == 2 and bar["colour"] == "rgb(165, 148, 255)", bar
    assert seen["note"] == "▍ time scale stretched where agents fan out", seen
    for ys in (seen["ticks"], seen["dense"]):
        assert len(ys) > 1 and all(b - a >= 18 for a, b in itertools.pairwise(ys)), ys


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
    burst = set(nodes["main"]["bursts"][0]["members"])  # drawn inside the collapsed group card, not as cards
    here = set(nodes["main"]["children"]) - burst
    assert {c["id"] for c in seen["mcp"] if c["ring"]} == had & here, seen["mcp"]
    assert {c["id"] for c in seen["mcp"] if c["dim"]} == here - had, seen["mcp"]
    assert [(g["ring"], g["dim"]) for g in seen["mcpGroup"]] == [(bool(had & burst), not had & burst)], seen["mcpGroup"]
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


@given("the served view carries a new version on every poll")
def step_bump_version(context):
    context.bump_version = True


@then("the page shows the view's own model, window, unknown facts, trigger words, notes, ratio and subagent counts")
def step_view_words(context):
    seen = _page(context, "words")
    if seen is None:
        return
    view = context.fixture
    assert view["model"] in seen["header"] and "1M window" in seen["header"], seen["header"]
    assert seen["unknown"] == "Not known: " + ", ".join(view["not_known"]) + ".", seen["unknown"]
    label = {t["key"]: t["label"] for t in view["adapter"]["triggers"]}
    assert any(label["session_start"] in title for title in seen["titles"]), seen["titles"]
    assert not any(
        old in title
        for title in seen["titles"]
        for old in ("at session start", "loaded by a path match", "inherited from its parent")
    ), seen["titles"]
    returned = next(n for n in view["nodes"] if n["id"] == "a1")["detail"]
    assert f"{returned['back_ratio']}:1 from peak" in seen["returned"], seen["returned"]
    assert ":1 from peak" not in seen["stopped"], seen["stopped"]
    main = next(n for n in view["nodes"] if n["id"] == "main")
    count = main["child_sources"]["mcp:docs-server"]
    assert f"{count} of {len(main['children'])} subagents here did" in seen["banner"], seen["banner"]
    assert "in 13 contexts" in seen["claudeRow"], seen["claudeRow"]


@then("a kind the view reports absent says so from its fact, and an untyped node adds no filter button but still shows")
def step_absent_and_untyped(context):
    seen = _page(context, "absent")
    if seen is None:
        return
    assert seen["absent"] == ["No skills configured"], seen
    assert "null" not in seen["typeButtons"], seen
    assert seen["untypedCard"] is True, seen


@then("a file opened while another file's check runs is checked once that check ends")
def step_autocheck_queue(context):
    seen = _page(context, "autocheck")
    if seen is None:
        return
    assert seen["second"] and "fixture finding" in seen["second"], seen
    posts = [line.split(" ", 2)[2] for line in context.handler.requests if line.startswith("POST")]
    assert posts == ["CLAUDE.md", ".claude/rules/rules-engine.md"], posts


@then("each failing command's text is fetched once however many times the view changes")
def step_call_fetched_once(context):
    seen = _page(context, "calls")
    if seen is None:
        return
    assert seen["bracket"].startswith("npm test"), seen
    assert context.handler.views_served >= 3, context.handler.views_served
    calls = [r for r in context.handler.requests if r.startswith("/call")]
    assert calls and len(calls) == len(set(calls)), calls


@then(
    "the inspector's panes start compact, open independently, stay open across agents, "
    "and print every estimate with a tilde"
)
def step_inspector_panes(context):
    seen = _page(context, "panes")
    if seen is None:
        return
    view = context.fixture
    nodes = {n["id"]: n for n in view["nodes"]}
    assert seen["start"]["context"]["open"] == "false" and seen["start"]["context"]["bodyHidden"], seen["start"]
    assert seen["start"]["cost"]["open"] == "false" and seen["start"]["cost"]["bodyHidden"], seen["start"]
    assert seen["contextOpen"]["open"] == "true" and not seen["contextOpen"]["bodyHidden"], seen["contextOpen"]
    assert seen["costAfterContext"]["open"] == "false", "opening Context must not open Cost"
    comp = nodes["main"]["detail"]["composition"]
    reply = comp["replies"][comp["peak"]]
    total, first = reply[1], 5
    assert [c["key"] for c in seen["categories"]] == [c["key"] for c in view["adapter"]["composition"]]
    remainder = view["adapter"]["composition_remainder"]
    for row in seen["categories"]:
        assert row["value"].startswith("~"), row
        want = "est. + remainder" if row["key"] == remainder else "estimated"
        assert row["tags"] == [want], row
    assert sum(reply[first : first + len(comp["keys"])]) == total, "fixture row must sum to its exact total"
    assert "exact" in seen["exactTag"] and _k1(total) in seen["contextOpen"]["head"], seen["contextOpen"]
    assert f"cache read {reply[4]:,}" in seen["contextText"], seen["contextText"]
    assert seen["costOpen"]["open"] == "true"
    price = view["price_list"]
    assert f"{price['name']}, {price['as_of']}" in seen["costText"], seen["costText"]
    assert "derived" in seen["costOpen"]["head"] and "cached" in seen["costOpen"]["head"], seen["costOpen"]
    assert "~$" in seen["costText"], "instruction-file cost is an estimate"
    after = seen["afterSelect"]
    assert after["context"]["open"] == "true" and after["cost"]["open"] == "true", after
    withheld = nodes["a1"]["withheld"]
    summary = f"Not passed down: {len(withheld['sources'])} sources · ~"
    compact = seen["withheldCompact"]
    assert summary in compact["head"] and compact["open"] == "false", compact
    assert seen["withheldRowsBefore"] == 0 and seen["withheldRowsAfter"] == len(withheld["sources"]), seen
    assert any(line.endswith("Agents · 2 defined, listed") for line in seen["mainChip"]), seen["mainChip"]
    assert any(line.endswith("Agents · built-in") for line in seen["a1Chip"]), seen["a1Chip"]
    definition = next(s for s in view["sources"] if s["kind"] == "agent" and "a3" in s["had_by"])
    name = definition["path"].rsplit("/", 1)[-1]
    assert any(line.endswith(f"Agents · {name}") for line in seen["a3Chip"]), seen["a3Chip"]
    for key, text in (("a1", seen["a1Text"]), ("main", seen["mainText"])):
        node = nodes[key]
        values = [g["tokens_est"] for g in node["detail"]["given"]]
        values += [p["tokens_est"] for p in node["detail"]["prompts"]]
        values += [s["tokens_est"] for s in (node.get("withheld") or {"sources": []})["sources"]]
        if node["detail"]["back_tokens_est"] is not None:
            values.append(node["detail"]["back_tokens_est"])
        assert values, key
        for value in values:
            shown = re.escape(_k1(value))
            assert value == 0 or not re.search(rf"(?<![~\w.,]){shown}(?![\w.,])", text), (key, value, text)
            assert f"~{_k1(value)}" in text, (key, value)


@then(
    "the Sources groups follow the adapter order with only the first open, expand and collapse all work, "
    "a long group shows four with a show-more, and focusing a source opens its group"
)
def step_source_groups(context):
    seen = _page(context, "groups")
    if seen is None:
        return
    order = [kind["key"] for kind in context.fixture["adapter"]["source_kinds"]]
    first = order[0]
    assert [g["kind"] for g in seen["initial"]] == order, seen["initial"]
    assert [g["kind"] for g in seen["initial"] if g["open"]] == [first], seen["initial"]
    assert all(not g["rows"] for g in seen["initial"] if g["kind"] != first), seen["initial"]
    assert all(g["open"] for g in seen["expanded"]), seen["expanded"]
    assert not any(g["open"] for g in seen["collapsed"]), seen["collapsed"]
    agents = [s["id"] for s in context.fixture["sources"] if s["kind"] == "agent"]
    assert len(agents) == 6, agents
    group = next(g for g in seen["agentOpen"] if g["kind"] == "agent")
    assert group["rows"] == agents[:4] and group["more"] == "Show 2 more", group
    group = next(g for g in seen["agentAll"] if g["kind"] == "agent")
    assert group["rows"] == agents and group["more"] == "Show fewer", group
    group = next(g for g in seen["agentFewer"] if g["kind"] == "agent")
    assert group["rows"] == agents[:4] and group["more"] == "Show 2 more", group
    assert not any(g["open"] for g in seen["closedAgain"]), seen["closedAgain"]
    focused = {g["kind"]: g for g in seen["focused"]}
    assert focused["agent"]["open"] and focused["agent"]["rows"] == agents, focused["agent"]
    assert [kind for kind, g in focused.items() if g["open"]] == ["agent"], focused
    instructions_sources = [s for s in context.fixture["sources"] if s["kind"] == "instructions"]
    findings = sum((s["findings"] or {}).get("count", 0) for s in instructions_sources)
    instructions = next(g for g in seen["initial"] if g["kind"] == "instructions")
    assert str(findings) in instructions["head"], instructions


@then(
    "a launched agent source lights exactly its subagents, a never-launched one lights nothing, the group ends "
    "with the adapter note, the A chip is filled or outlined by count and the toolbar has a toggle per adapter kind"
)
def step_agent_sources(context):
    seen = _page(context, "agents")
    if seen is None:
        return
    sources = {s["id"]: s for s in context.fixture["sources"] if s["kind"] == "agent"}
    rows = seen["rows"]
    reviewer = rows[".claude/agents/reviewer.md"]
    assert reviewer["name"] == ".claude/agents/reviewer.md", reviewer
    assert reviewer["who"] == "launched as 2 subagents · passed down as its system prompt", reviewer
    assert reviewer["pill"] is True, reviewer
    assert rows[".claude/agents/planner.md"]["who"] == "launched as 1 subagent · passed down as its system prompt", rows
    assert rows[".claude/agents/idle.md"]["who"] == "defined, never launched", rows
    here = set(context.fixture["nodes"][0]["children"])
    lit = seen["lit"]
    assert set(lit[".claude/agents/reviewer.md"]) == set(sources[".claude/agents/reviewer.md"]["had_by"]) & here, lit
    assert lit[".claude/agents/idle.md"] == [] and lit[".claude/agents/idle.md top"] is False, lit
    notes = [kind["note"] for kind in context.fixture["adapter"]["source_kinds"] if kind["key"] == "agent"]
    assert notes and notes[0] and seen["note"] == notes[0], (notes, seen["note"])
    chips = seen["chips"]

    def filled(name: str) -> bool:
        return bool({"on", "find"} & set(chips[name].split()))

    assert filled("a3") and filled("a4"), chips  # launched from a definition
    assert not filled("a1") and not filled("a5"), chips  # built-in types: outlined
    letters = [f"{kind['key']}:{kind['letter']}" for kind in context.fixture["adapter"]["source_kinds"]]
    assert seen["toggles"] == letters, seen["toggles"]
    assert "agent:A" in letters and "hook:H" in letters, letters


@then("an instructions source row shows its cost as an estimate and a source without one shows none")
def step_source_cost(context):
    seen = _page(context, "cost")
    if seen is None:
        return
    assert "~$0.01 estimated" in seen["claude"] and "~$0.01 estimated" in seen["other"], seen
    assert "$" not in seen["rule"], seen


def _points(text: str) -> list[tuple[float, float]]:
    return [(float(a), float(b)) for a, b in (pair.split(",") for pair in text.split())]


@then(
    "the spine is about 18 pixels wide each side at the peak reply, narrower at the first, "
    "its bands fill it in the adapter's order and the legend says so"
)
def step_spine_bands(context):
    seen = _page(context, "p4spine")
    if seen is None:
        return
    assert seen["legend"] == "spine width = context (exact) \u00b7 bands = composition (estimated)", seen["legend"]
    outline = _points(seen["outline"])
    n = len(outline) // 2
    width = [outline[2 * n - 1 - k][0] - outline[k][0] for k in range(n)]  # the right edge is stored reversed
    main = next(node for node in context.fixture["nodes"] if node["id"] == "main")
    replies = main["detail"]["composition"]["replies"]
    peak = max(r[1] for r in replies)
    assert abs(max(width) / 2 - 18) < 0.2, max(width)
    assert abs(width[0] / 2 - (2 + 16 * replies[0][1] / peak)) < 0.2, (width[0], replies[0][1], peak)
    order = [c["key"] for c in context.fixture["adapter"]["composition"]]
    assert [b["key"] for b in seen["bands"]] == order, seen["bands"]
    shapes = [_points(b["points"]) for b in seen["bands"]]
    for k in range(n):
        total = sum(pts[2 * n - 1 - k][0] - pts[k][0] for pts in shapes)
        assert abs(total - width[k]) <= 1.0, (k, total, width[k])
    for left, right in itertools.pairwise(shapes):  # stacked left to right, each starting where the last ended
        assert all(abs(right[k][0] - left[2 * n - 1 - k][0]) <= 0.2 for k in range(n))
    assert {b["opacity"] for b in seen["bands"]} == {"0.5"}, seen["bands"]


@then("a hook stretch draws one pill with its count and tokens, and three close loads draw one pill naming all three")
def step_hook_and_merge(context):
    seen = _page(context, "p4stations")
    if seen is None:
        return
    hooks = [s for s in seen["stations"] if s["kind"] == "hook"]
    assert len(hooks) == 1, seen["stations"]
    assert re.fullmatch(r"H\u00d7120 \u00b7 ~58k", hooks[0]["text"]), hooks[0]
    assert not [s for s in seen["stations"] if s["source"].startswith("hook:") and s["kind"] != "hook"], seen[
        "stations"
    ]
    merged = [s for s in seen["stations"] if s["kind"] == "merged"]
    assert len(merged) == 1 and merged[0]["tag"] == "BUTTON", seen["stations"]
    assert merged[0]["text"] == "3 loads", merged[0]
    lines = merged[0]["title"].split("\n")
    assert len(lines) == 3 and all(" \u00b7 ~" in line for line in lines), merged[0]
    assert merged[0]["label"].startswith("3 loads: "), merged[0]
    members = merged[0]["sources"].split()
    assert len(members) == 3 and merged[0]["source"] == members[0], merged[0]
    assert seen["pinned"], seen  # a click focuses the first member: the focus banner names it


@then("no handoff pill exists until an agent is selected, then its two show")
def step_handoff_pills(context):
    seen = _page(context, "p4pills")
    if seen is None:
        return
    assert seen["none"] == [], seen
    assert len(seen["selected"]) == 2 and seen["selected"][0].startswith("\u2193"), seen
    assert seen["selected"][1].startswith("\u2191"), seen
    assert len(seen["member"]) == 2, seen
    assert seen["cleared"] == [], seen


@then(
    "a long card title wraps to two lines, the subtitle has no type label and the title attribute holds the full name"
)
def step_card_title(context):
    seen = _page(context, "p4cards")
    if seen is None:
        return
    names = {node["id"]: node["name"] for node in context.fixture["nodes"]}
    cards = {c["id"]: c for c in seen["cards"]}
    long = cards["a2"]
    assert long["title"] == names["a2"] and long["name"] == names["a2"], long
    assert long["lines"] == 2, long  # an 80-character task wraps to two lines and ends there
    for card in cards.values():
        assert card["lines"] <= 2 and card["fits"] is True, card
        assert card["title"] == names[card["id"]], card
        assert re.fullmatch(r"\d+[ms]( \d+s)?", card["sub"]), card  # a duration, no type label


@then("a subagent launched at the start and an expanded fan-out box sit below the top card and touch no card")
def step_top_card_clear(context):
    for width in (1440, 925):
        seen = _page(context, "fxtop", width)
        if seen is None:
            return
        for state in (seen, seen["expanded"]):
            assert state["overlaps"] == 0 and state["boxHits"] == 0, (width, state)
        assert abs(seen["early"]["top"] + 18 - seen["early"]["launchY"]) < 0.6, (
            width,
            seen,
        )  # still at its launch time
        assert seen["boxTop"] >= seen["topBottom"] - 0.6, (width, seen)


@then("no station pill overlaps a card at 1440 and at 925 pixels")
def step_stations_clear(context):
    for width in (1440, 925):
        seen = _page(context, "overlap", width)
        if seen is None:
            return
        assert seen["stations"] > 0, (width, seen)
        assert seen["stationHits"] == 0, (width, seen)


@then("every group card line and its expand label sit inside the card at 1440 and at 925 pixels")
def step_group_text_inside(context):
    for width in (1440, 925):
        seen = _page(context, "fxgroup", width)
        if seen is None:
            return
        assert len(seen["groups"]) == 2, seen
        for group in seen["groups"]:
            assert group["expand"] and group["over"] == 0, (width, group)


@then("going up a level from a member of a collapsed group selects the member and shows its group expanded")
def step_up_opens_group(context):
    seen = _page(context, "fxup")
    if seen is None:
        return
    assert seen["before"] is False, seen
    assert seen["sel"] == "a1" and seen["afterUp"] is True, seen


@then(
    "a source row, the focus banner and a load station's tooltip print their token counts "
    "with a tilde and the word estimated"
)
def step_estimates_tilde(context):
    seen = _page(context, "fxbare")
    if seen is None:
        return
    assert seen["rows"] and seen["titles"], seen
    for text in seen["rows"]:
        assert re.search(r"~[\d.]+k? each \(estimated\)", text), text
    assert re.search(r"~[\d.]+k? each \(estimated\)", seen["focus"]), seen["focus"]
    for title in seen["titles"]:
        assert re.search(r"~[\d.]+k? loaded \(estimated\)", title), title


@then("the cost pane says replies were not priced because no model was named, and lists the models when there are some")
def step_unpriced_wording(context):
    seen = _page(context, "fxcost")
    if seen is None:
        return
    assert seen["main"] == ["2 replies not priced (no model named)"], seen
    assert seen["member"] == ["1 reply not priced: claude-unlisted-1"], seen
