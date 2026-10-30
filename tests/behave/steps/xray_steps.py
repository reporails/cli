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
from pathlib import Path

from behave import given, then, when  # type: ignore[import-untyped]
from support import AILS_BIN, build_project, run_ails  # behave puts features/ on sys.path

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


@then("the page carries a launch token and the session view with that token has turns")
def step_view(context):
    status, page = _get(context.url)
    assert status == 200
    token = re.search(r'name="xray-token" content="([^"]+)"', page)
    assert token and token.group(1) != "__XRAY_TOKEN__", "the page carries no launch token"
    status, body = _get(context.url + "view", token.group(1))
    assert status == 200, status
    assert len(json.loads(body)["turns"]) > 0


@then("headless Chrome rendering the page shows the context window map, not a server error")
def step_browser(context):
    chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
    if chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no Chrome or Chromium on PATH, the page was not rendered")
        return
    dom = subprocess.run(
        [chrome, "--headless=new", "--disable-gpu", "--virtual-time-budget=8000", "--dump-dom", context.url],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    ).stdout
    assert "did not answer" not in dom, "the page could not read its session view"
    assert "Context window, turn by turn" in dom, dom[:500]


@then("the session view without the token is refused with 403")
def step_no_token(context):
    assert _get(context.url + "view")[0] == 403


@then("it exits 2 saying no Claude Code session was found")
def step_refused(context):
    assert context.result.returncode == 2, context.result.returncode
    assert "no Claude Code session found" in context.result.stderr
