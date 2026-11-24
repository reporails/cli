"""Step definitions for the x-ray guard health demonstration: a project whose settings declare hooks, one with a
script that lost its executable bit, and the real page driven in a browser."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from behave import given, then  # type: ignore[import-untyped]
from steps.xray_harness_steps import _append_attachment

SCRIPT = Path(__file__).resolve().parents[1] / "xray_guard_health.mjs"
RAN = "ran.sh"
SILENT = "silent.sh"


@given("the project's settings declare a hook whose script ran and a hook whose script is not executable")
def step_declare(context):
    hooks = context.project / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    for name, mode in ((RAN, 0o755), (SILENT, 0o644)):
        (hooks / name).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (hooks / name).chmod(mode)
    handlers = [{"type": "command", "command": f'"$CLAUDE_PROJECT_DIR"/.claude/hooks/{name}'} for name in (RAN, SILENT)]
    settings = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": handlers}]}}
    (context.project / ".claude" / "settings.json").write_text(json.dumps(settings), encoding="utf-8")


@given("the session recorded the first hook running")
def step_ran(context):
    attachment = {
        "type": "hook_success",
        "hookName": "PreToolUse:Bash",
        "hookEvent": "PreToolUse",
        "toolUseID": "toolu_1",
        "command": f'"{context.project}"/.claude/hooks/{RAN}',
        "exitCode": 0,
        "durationMs": 7,
        "stdout": "",
        "stderr": "",
        "content": "",
    }
    _append_attachment(context, 1, attachment, uuid="hook-row-0001")


def _page(context) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    if getattr(context, "guard_page", None) is None:
        done = subprocess.run(
            [node, str(SCRIPT), context.url],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
            env={**os.environ, "CHROME_BIN": chrome},
        )
        assert done.returncode == 0, done.stderr
        context.guard_page = json.loads(done.stdout.strip().splitlines()[-1])
        assert context.guard_page["ready"], "the page did not draw the Hooks group"
    return context.guard_page


def _row(seen: dict, word: str) -> dict:
    return next(row for row in seen["rows"] if word in row["name"] or word in row["facts"])


@then('the Hooks group header reads fired of declared with "{alert}" and stays closed until opened')
def step_header(context, alert):
    seen = _page(context)
    if seen is None:
        return
    header = seen["header"]
    declared = len(seen["rows"])
    fired = sum(1 for row in seen["rows"] if row["facts"].startswith("fired "))
    assert (header["used"], header["total"]) == (str(fired), f"/{declared}"), (header, seen["rows"])
    assert (fired, declared) == (1, 2), seen["rows"]
    assert alert in header["subs"], header
    assert seen["autoOpen"] is False, "the alert opened the group by itself"


@then("the broken hook's row reads \"{phrase}\" and the fired hook's row reads its count and last time")
def step_rows(context, phrase):
    seen = _page(context)
    if seen is None:
        return
    broken = _row(seen, SILENT)
    assert broken["facts"] == phrase, broken
    fired = next(row for row in seen["rows"] if row["facts"].startswith("fired "))
    assert re.fullmatch(r"fired 1\u00d7 \u00b7 last \d+:\d\d", fired["facts"]), fired


@then('the broken hook\'s details open on a Health section naming the event, the matcher and "chmod +x" for its script')
def step_details(context):
    seen = _page(context)
    if seen is None:
        return
    details = seen["details"]
    assert details["titles"][0] == "Health", details
    health = details["health"]
    script = context.project / ".claude" / "hooks" / SILENT
    for expected in ("event: PreToolUse", "matcher: Bash", "never fired · not executable", f"chmod +x {script}"):
        assert expected in health, (expected, health)


@then("the Sources table says the same phrase in the In context column and the page added no tab")
def step_table(context):
    seen = _page(context)
    if seen is None:
        return
    row = next(cells for cells in seen["table"] if SILENT in cells[1])
    assert row[3] == "never fired · not executable", row
    assert seen["tabs"] == ["graph", "calls", "sources"], seen["tabs"]


@then("every request the page made went to the address that served it")
def step_offline(context):
    seen = _page(context)
    if seen is None:
        return
    here = urlparse(context.url).netloc
    asked = {urlparse(name).netloc for name in seen["requests"] + seen["resourcesAfter"]}
    assert asked == {here}, asked
