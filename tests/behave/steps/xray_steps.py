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
from itertools import pairwise
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


@given('the project\'s instruction file reads "{text}"')
def step_instruction_text(context, text):
    (context.project / "CLAUDE.md").write_text(text + "\n", encoding="utf-8")


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


def _rendered_dom(context) -> str | None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
    if chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no Chrome or Chromium on PATH, the page was not rendered")
        return None
    return subprocess.run(
        [chrome, "--headless=new", "--disable-gpu", "--virtual-time-budget=8000", "--dump-dom", context.url],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=90,
        check=False,
    ).stdout


@then("headless Chrome rendering the page shows the context window map, not a server error")
def step_browser(context):
    dom = _rendered_dom(context)
    if dom is None:
        return
    assert "did not answer" not in dom, "the page could not read its session view"
    assert "Context window, turn by turn" in dom, dom[:500]


@then("the drawn reply points of each turn equal that turn's reply contexts in the view")
def step_reply_points(context):
    dom = _rendered_dom(context)
    if dom is None:
        return
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    turns = json.loads(_get(context.url + "view", token)[1])["turns"]
    drawn: dict[int, list[int]] = {}
    for turn, ctx in re.findall(r'<circle class="rp" data-turn="(\d+)" data-ctx="(\d+)"', dom):
        drawn.setdefault(int(turn), []).append(int(ctx))
    for turn in turns:
        expected = [point[1] for point in turn["series"]]
        assert drawn.get(turn["n"], []) == expected, (turn["n"], drawn.get(turn["n"]), expected)
    context.view_turns = turns
    context.dom = dom


@then('each turn row is labelled "turn N · M replies"')
def step_row_labels(context):
    if not getattr(context, "dom", None):
        return
    labels = re.findall(r'<text class="rlab[^"]*"[^>]*>([^<]*)</text>', context.dom)
    for turn in context.view_turns:
        word = "reply" if turn["replies"] == 1 else "replies"
        assert f"turn {turn['n']} \u00b7 {turn['replies']} {word}" in labels, (turn["n"], labels[:5])


@then("the turn labels sit left of the river spine and no two are closer than their font size")
def step_label_layout(context):
    if not getattr(context, "dom", None):
        return
    css = _get(context.url + "xray.css")[1]
    size = float(re.search(r"\.map \.rlab\{[^}]*font:([\d.]+)px", css).group(1))
    spine = float(re.search(r'<line class="spine" x1="([\d.]+)"', context.dom).group(1))
    labels = re.findall(r'<text class="rlab[^"]*" x="([\d.]+)" y="([\d.]+)"', context.dom)
    assert len(labels) >= len(context.view_turns), len(labels)
    assert all(float(x) < spine for x, _ in labels), (spine, labels[:3])
    ys = [float(y) for _, y in labels]
    gaps = [b - a for a, b in pairwise(ys)]
    assert all(gap >= size + 2 for gap in gaps), (size, min(gaps))


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
