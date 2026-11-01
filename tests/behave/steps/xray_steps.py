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


@then("headless Chrome rendering the page shows the context window chart, not a server error")
def step_browser(context):
    dom = _rendered_dom(context)
    if dom is None:
        return
    assert "did not answer" not in dom, "the page could not read its session view"
    assert '<svg class="chart"' in dom, dom[:500]


def _view_turns(context) -> list[dict]:
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    return json.loads(_get(context.url + "view", token)[1])["turns"]


@then("the drawn main-session points of each turn equal that turn's series in the view")
def step_reply_points(context):
    dom = _rendered_dom(context)
    if dom is None:
        return
    turns = _view_turns(context)
    drawn: dict[int, list[int]] = {}
    for turn, ctx in re.findall(r'<circle class="rp" data-turn="(\d+)" data-ctx="(\d+)"', dom):
        drawn.setdefault(int(turn), []).append(int(ctx))
    for turn in turns:
        expected = [point[1] for point in turn["series"]]
        assert drawn.get(turn["n"], []) == expected, (turn["n"], drawn.get(turn["n"]), expected)
    context.view_turns = turns
    context.dom = dom


@then("each turn is labelled with its number and its reply count")
def step_row_labels(context):
    if not getattr(context, "dom", None):
        return
    headers = dict(re.findall(r'data-turnh="(\d+)"[^>]*>(.*?)</div>', context.dom))
    for turn in context.view_turns:
        word = "reply" if turn["replies"] == 1 else "replies"
        header = re.sub(r"<[^>]+>", " ", headers[str(turn["n"])])
        assert f"turn {turn['n']}" in header and f"{turn['replies']} {word}" in header, (turn["n"], header)


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


@then("no two chart labels overlap at 925 and at 1440 pixels")
def step_no_overlap(context):
    for width in ("925", "1440"):
        seen = _layout_script(context, "layout", width)
        if seen is None:
            return
        assert seen["ready"], f"the page did not draw at {width} px"
        assert seen["labels"] > 0 and seen["overlaps"] == 0, (width, seen)


@then(
    "at 925 pixels the chart ends inside the first 1000 pixels and the artifact list is left of the information display"
)
def step_first_screen(context):
    seen = _layout_script(context, "layout", "925")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    assert seen["chartBottom"] is not None and seen["chartBottom"] <= 1000, seen
    assert seen["artRight"] is not None and seen["infoLeft"] is not None, seen
    assert seen["artRight"] <= seen["infoLeft"] and abs(seen["artTop"] - seen["infoTop"]) < 2, seen


@then('selecting the not-loaded memory file shows "{text}"')
def step_memory_selected(context, text):
    seen = _layout_script(context, "memory")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    assert seen["row"] == "orphan", seen
    assert text in seen["text"], seen


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


def _full_view(context) -> dict:
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    return json.loads(_get(context.url + "view", token)[1])


@then("the page draws a band and a line for each of the two compactions and the first band ends at the second line")
def step_two_bands(context):
    seen = _layout_script(context, "facts")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    compactions = _full_view(context)["compactions"]
    assert len(compactions) == 2, compactions
    assert len(seen["bands"]) == 2 and len(seen["lines"]) == 2, seen
    first, second = seen["bands"]
    assert abs(seen["lines"][0] - first["x"]) < 0.01 and abs(seen["lines"][1] - second["x"]) < 0.01, seen
    assert abs(first["x"] + first["w"] - seen["lines"][1]) < 0.01, ("first band must end at the second line", seen)
    assert first["w"] > 1 and second["w"] >= 1, seen


def _k1(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1e6:.0f}M" if n >= 10_000_000 else f"{n / 1e6:.2f}".rstrip("0").rstrip(".") + "M"
    if n >= 1000:
        return f"{n / 1000:.0f}k" if n >= 10_000 else f"{n / 1000:.1f}".removesuffix(".0") + "k"
    return str(n)


def _clock(t: float) -> str:
    t = max(0, round(t))
    hours, minutes, seconds = t // 3600, t % 3600 // 60, t % 60
    return f"{hours}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes}:{seconds:02d}"


@then("the header peak, each turn's start, its prompt numbers and its Stop count are the view's own values")
def step_view_facts(context):
    seen = _layout_script(context, "facts")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    view = _full_view(context)
    assert f"peak {_k1(view['peak'])}" in seen["header"], (seen["header"], view["peak"])
    by_turn = {tag["n"]: tag for tag in seen["tags"]}
    for turn in view["turns"]:
        tag = by_turn[turn["n"]]
        assert tag["start"] == _clock(turn["start"]), (tag, turn["start"])
        for prompt in turn["prompts"]:
            assert str(prompt["no"]) in tag["label"], (tag, prompt["no"])
        assert (f"{turn['stop_blocks']} Stop" in tag["rt"]) == (turn["stop_blocks"] > 0), (tag, turn["stop_blocks"])


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
