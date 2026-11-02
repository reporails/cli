"""Step definitions for opening x-ray sessions: the real `ails` binary, the real MCP server and the page over HTTP."""

from __future__ import annotations

import asyncio
import json
import os
import re
import selectors
import shutil
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

from behave import given, then, when  # type: ignore[import-untyped]
from support import AILS_BIN, MCP_BIN, build_project, run_ails  # behave puts features/ on sys.path

from reporails_cli.core.discovery.agent_discovery import claude_project_folder_name
from reporails_cli.core.xray.pages import PAGE_START_S
from tests.suite_env import suite_env

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript" / "2.1.308"
OLDER, NEWER = "older-session", "newer-session"
SESSION_ENV = "CLAUDE_CODE_SESSION_ID"
ADDRESS = re.compile(r"http://127\.0\.0\.1:\d+/\?session=\S+")
PAGE_ADDRESS = re.compile(r"http://127\.0\.0\.1:\d+/")


def _get(url: str, token: str | None = None) -> str:
    request = urllib.request.Request(url, headers={"X-Xray-Token": token} if token else {})
    with urllib.request.urlopen(request, timeout=30) as reply:
        return reply.read().decode("utf-8")


def _token(base: str) -> str:
    found = re.search(r'name="xray-token" content="([^"]+)"', _get(base))
    assert found, "the page carries no launch token"
    return found.group(1)


def _base(url: str) -> str:
    return url.split("?", 1)[0]


def _view_of(url: str) -> dict:
    """The session view the page at `url` (its own query string included) would fetch."""
    query = url.partition("?")[2]
    base = _base(url)
    return json.loads(_get(f"{base}view" + (f"?{query}" if query else ""), _token(base)))


@given("a project with two recorded Claude Code sessions, the older one written first")
def step_two_sessions(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    folder = context.home / ".claude" / "projects" / claude_project_folder_name(context.project)
    folder.mkdir(parents=True)
    text = (FIXTURE / "session.jsonl").read_text(encoding="utf-8").replace("/work/proj", str(context.project))
    older = folder / f"{OLDER}.jsonl"
    older.write_text(text, encoding="utf-8")
    hour_ago = time.time() - 3600
    os.utime(older, (hour_ago, hour_ago))
    shutil.copytree(FIXTURE / "session", folder / NEWER)
    (folder / f"{NEWER}.jsonl").write_text(text, encoding="utf-8")


@then("the page lists both sessions with start time, length and subagent count")
def step_lists_sessions(context):
    base = _base(context.url)
    body = json.loads(_get(f"{base}sessions", _token(base)))
    by_id = {entry["session"]: entry for entry in body["sessions"]}
    assert set(by_id) == {OLDER, NEWER}, body
    assert body["session"] == NEWER, "the page opens on the newest session"
    for entry in by_id.values():
        assert entry["started_at"] and entry["length_s"] is not None, entry
    assert by_id[NEWER]["subagents"] >= 1 and by_id[OLDER]["subagents"] == 0, by_id
    context.launch_before = json.loads(_get(f"{base}launch"))["launch"]


@then("the older session's view is served by the same running page process")
def step_older_view(context):
    base = _base(context.url)
    assert _view_of(f"{base}?session={OLDER}")["session"] == OLDER
    assert _view_of(base)["session"] == NEWER
    assert json.loads(_get(f"{base}launch"))["launch"] == context.launch_before, "the page process was restarted"


@then("picking the older session in the header shows that session on the page")
def step_pick_in_header(context):
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return
    script = Path(__file__).resolve().parents[1] / "xray_page.mjs"
    done = subprocess.run(
        [node, str(script), context.url, "pickother", "1440", OLDER],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout.strip().splitlines()[-1])
    assert seen["ready"], seen
    assert f"Session {NEWER}." in seen["firstSrc"], seen
    assert set(seen["listed"]) == {OLDER, NEWER} and seen["noIdTyped"], seen
    assert seen["search"] == f"?session={OLDER}" and f"Session {OLDER}." in seen["src"], seen


def _mcp_env(context, session: str = "") -> dict[str, str]:
    return {**suite_env(os.environ), "HOME": str(context.home), "USERPROFILE": str(context.home), SESSION_ENV: session}


async def _xray_calls(project: Path, env: dict[str, str], *, together: bool) -> list[tuple[dict, float]]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    assert MCP_BIN is not None, "`reporails-mcp` console script not on PATH (run via `uv run behave`)"

    async def call(session: ClientSession) -> tuple[dict, float]:
        began = time.monotonic()
        reply = await session.call_tool("xray", {"path": str(project)})
        assert not reply.is_error, f"MCP xray errored: {reply.content}"
        return json.loads(reply.content[0].text), time.monotonic() - began

    params = StdioServerParameters(command=str(MCP_BIN), env=env, cwd=str(project))
    with open(os.devnull, "w", encoding="utf-8") as server_log:
        async with stdio_client(params, errlog=server_log) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            if together:
                return list(await asyncio.gather(call(session), call(session)))
            return [await call(session), await call(session)]


def _mcp_calls(context, *, together: bool, session: str = "") -> None:
    context.mcp = asyncio.run(
        asyncio.wait_for(
            _xray_calls(context.project, _mcp_env(context, session), together=together), timeout=PAGE_START_S * 3
        )
    )


def _port(reply: dict) -> str:
    found = re.match(r"http://127\.0\.0\.1:(\d+)/", reply["url"])
    assert found, reply
    return found.group(1)


@when("the MCP server's xray tool is called twice one after the other")
def step_mcp_twice(context):
    _mcp_calls(context, together=False)


@when("the MCP server's xray tool is called twice at the same moment")
def step_mcp_together(context):
    _mcp_calls(context, together=True)


@then("the first call answered with an address well inside the page start limit")
def step_mcp_fast(context):
    (first, took), _ = context.mcp
    assert "url" in first, first
    assert took < PAGE_START_S / 2, f"the call took {took:.1f}s of {PAGE_START_S:.0f}s"
    context.url = first["url"]


@then("the address's page answers as the x-ray page")
def step_mcp_page_answers(context):
    launch = json.loads(_get(_base(context.url) + "launch"))
    assert launch["launch"], launch


@then("the second call returned the same port marked reused")
def step_mcp_reused(context):
    (first, _), (second, _) = context.mcp
    assert _port(second) == _port(first) and second["reused"] is True and first["reused"] is False, context.mcp


@then("both calls returned the same port")
def step_mcp_same_port(context):
    (first, _), (second, _) = context.mcp
    assert "url" in first and "url" in second, context.mcp
    assert _port(first) == _port(second), context.mcp
    assert sorted([first["reused"], second["reused"]]) == [False, True], context.mcp


def _run_current(context, session_env: str, *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    context.result = run_ails(
        cwd or context.project,
        "xray",
        "--current",
        "--background",
        "--no-open",
        home=context.home,
        timeout=120,
        env={SESSION_ENV: session_env, **(env or {})},
    )
    assert context.result.returncode == 0, context.result.stderr
    found = ADDRESS.search(context.result.stdout)
    assert found, f"no session address printed: {context.result.stdout!r}"
    context.url = found.group(0)


@when('"ails xray --current --background --no-open" is run in the project as the agent of the older session')
def step_current_known(context):
    _run_current(context, OLDER)


@when('"ails xray --current --background --no-open" is run in the project by an agent that does not say its session')
def step_current_unknown(context):
    _run_current(context, "")


@when('"ails xray --current --background --no-open" is run in a project subfolder as the agent of the older session')
def step_current_in_subfolder(context):
    subfolder = context.project / "src" / "pkg"
    subfolder.mkdir(parents=True)
    _run_current(context, OLDER, cwd=subfolder)


@when('"ails xray --current --background --no-open" is run in the project with a 2 second idle window')
def step_current_idle_window(context):
    _run_current(context, "", env={"AILS_XRAY_IDLE_S": "2"})


@then("within 15 seconds the page no longer answers and the project has no page record")
def step_page_stopped(context):
    records = context.home / ".reporails" / "xray-pages"
    port = int(_base(context.url).rsplit(":", 1)[1].rstrip("/"))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:  # a bare connect sends no request, so it does not keep the page in use
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        except OSError:
            if not list(records.glob("*.json")):
                return
        time.sleep(0.5)
    raise AssertionError(f"the page still answers or left its record: {list(records.glob('*.json'))}")


@then("the printed address names the older session")
def step_names_older(context):
    assert f"x-ray of session {OLDER}:" in context.result.stdout and f"?session={OLDER}" in context.url


@then("the page at that address shows the older session as the current one")
def step_older_current(context):
    view = _view_of(context.url)
    assert (view["session"], view["picked"]) == (OLDER, "current"), view


@then("the printed address names the newest session and says the agent did not say which session it is")
def step_names_newest(context):
    assert f"?session={NEWER}" in context.url, context.url
    assert "the agent did not say which session it is" in context.result.stdout, context.result.stdout


@then("the page at that address shows the newest session marked as not known to be the agent's own")
def step_newest_unknown(context):
    view = _view_of(context.url)
    assert (view["session"], view["picked"]) == (NEWER, "current_unknown"), view


MARKER = "PROJECT CODE RAN"


@given('the project root holds "typer.py" and "httpx.py" that print a marker and exit non-zero')
def step_hostile_modules(context):
    for name in ("typer.py", "httpx.py"):
        (context.project / name).write_text(f'print("{MARKER}")\nraise SystemExit(3)\n', encoding="utf-8")


@then("the printed address answers as the x-ray page")
def step_address_answers(context):
    assert json.loads(_get(_base(context.url) + "launch"))["launch"]


@then("the project's marker was never printed")
def step_no_marker(context):
    assert MARKER not in context.result.stdout + context.result.stderr


@when('"ails xray --current --no-open" is left running in the project with the session variable unset')
def step_foreground_page(context):
    assert AILS_BIN is not None, "`ails` console script not on PATH (run via `uv run behave`)"
    env = {**_mcp_env(context), "PYTHONUNBUFFERED": "1", "NO_COLOR": "1", "COLUMNS": "200"}
    proc = subprocess.Popen(  # pylint: disable=consider-using-with  # stopped by the cleanup below
        [str(AILS_BIN), "xray", "--current", "--no-open"],
        cwd=str(context.project),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )

    def stop() -> None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    context.add_cleanup(stop)
    assert proc.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    deadline, seen = time.monotonic() + PAGE_START_S, ""
    while time.monotonic() < deadline and not PAGE_ADDRESS.search(seen):
        if selector.select(timeout=0.5):
            seen += proc.stdout.readline()
    found = PAGE_ADDRESS.search(seen)
    assert found, f"no page address printed: {seen!r}"
    context.foreground_url = found.group(0)


@when("the MCP server's xray tool is called by the agent of the newest session")
def step_mcp_newest(context):
    _mcp_calls(context, together=False, session=NEWER)
    context.url = context.mcp[0][0]["url"]


@then("the returned address is on the running page's port")
def step_same_page(context):
    assert _port(context.mcp[0][0]) == _port({"url": context.foreground_url}), (context.mcp, context.foreground_url)
    assert context.mcp[0][0]["reused"] is True


@then("the page at the returned address shows the newest session as the current one")
def step_newest_current(context):
    view = _view_of(context.url)
    assert (view["session"], view["picked"]) == (NEWER, "current"), view
