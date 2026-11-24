"""Step definitions for the x-ray load groups: a synthetic session whose hook firing is followed by instruction loads,
the real `ails xray` binary and its page."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

from behave import given, then  # type: ignore[import-untyped]
from steps.xray_steps import _get, _reply, _row, _usage  # behave puts features/ on sys.path
from support import build_project

from reporails_cli.core.discovery.agent_discovery import claude_project_folder_name

SCRIPT = Path(__file__).resolve().parents[1] / "xray_load_groups.mjs"
HOOK = "PreToolUse:Read"
FILES = ("docs/a/CLAUDE.md", "docs/b/CLAUDE.md")
# The order the four loads arrive in: the first file three times, the second once.
LOADS = (0, 1, 0, 0)


def _at(minute: int, second: int = 0) -> dict:
    return {"timestamp": f"2026-10-31T10:{minute:02d}:{second:02d}.000Z"}


def _session(project: Path, *, said: str | None) -> list[dict]:
    """A main agent that worked for an hour; at minute 10 a hook fired (`said` is its output) and, within four
    seconds, four nested instruction files loaded."""
    version = "2.1.309"
    rows = [
        _row(
            "user",
            0,
            version,
            project,
            uuid="p-one",
            promptSource="typed",
            origin={"kind": "human"},
            message={"role": "user", "content": "go"},
            **_at(0),
        ),
        _reply(1, version, project, "msg_1", [{"type": "text", "text": "ok"}], _usage(1000, 300), "req-1") | _at(1),
    ]
    if said is not None:
        firing = {
            "type": "hook_success",
            "hookName": HOOK,
            "hookEvent": "PreToolUse",
            "toolUseID": "toolu_1",
            "command": "echo go",
            "exitCode": 0,
            "durationMs": 5,
            "stdout": said,
            "stderr": "",
            "content": "",
        }
        rows.append(_row("attachment", 0, version, project, attachment=firing, uuid="hook-1", **_at(10)))
    for number, which in enumerate(LOADS):
        attachment = {"type": "nested_memory", "path": str(project / FILES[which]), "content": {"content": "x"}}
        rows.append(_row("attachment", 0, version, project, attachment=attachment, **_at(10, 1 + number)))
    rows.append(
        _reply(2, version, project, "msg_2", [{"type": "text", "text": "done"}], _usage(5000, 800), "req-2") | _at(30)
    )
    rows.append(
        _reply(3, version, project, "msg_3", [{"type": "text", "text": "bye"}], _usage(9000, 900), "req-3") | _at(59)
    )
    return rows


def _write(context, name: str, *, said: str | None) -> None:
    root = context.tmpdir / name
    root.mkdir()
    project = build_project(root).resolve()
    for relative in FILES:
        target = project / relative
        target.parent.mkdir(parents=True)
        target.write_text(f"# {relative}\n\nKeep this folder tidy.\n" * 40, encoding="utf-8")
    home = root / "home"
    folder = home / ".claude" / "projects" / claude_project_folder_name(project)
    folder.mkdir(parents=True)
    rows = _session(project, said=said)
    (folder / "session.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    setattr(context, f"{name}_project", project)
    setattr(context, f"{name}_home", home)


@given(
    "a project whose session had a hook fire and four instruction loads "
    "follow within seconds, one file loaded three times"
)
def step_session(context):
    _write(context, "grouped", said="read the docs first")
    _write(context, "bare", said="")
    context.project, context.home = context.grouped_project, context.grouped_home


def _view(url: str) -> dict:
    status, page = _get(url)
    assert status == 200, status
    token = re.search(r'name="xray-token" content="([^"]+)"', page)
    assert token, "the page carries no launch token"
    status, body = _get(url + "view", token.group(1))
    assert status == 200, status
    return json.loads(body)


def _main_station(view: dict) -> dict:
    return next(station for station in view["stations"] if station["node"] == "main")


@then(
    "the view holds one group naming the hook with four loads of two "
    "files, the repeated file counted three times, and the station keeps none of those loads"
)
def step_view(context):
    view = _view(context.url)
    station = _main_station(view)
    (group,) = station["groups"]
    assert group["hook"] == f"hook:{HOOK}", group
    assert group["count"] == 4 and len(group["files"]) == 2, group
    assert sorted(f["count"] for f in group["files"]) == [1, 3], group
    labels = {source["id"]: source["label"] for source in view["sources"]}
    grouped = {labels[f["source"]] for f in group["files"]}
    assert not [load for load in station["loads"] if labels.get(load["source"]) in grouped], station["loads"]
    context.grouped_view = view


def _page(context, width: int) -> dict:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return {}
    done = subprocess.run(
        [node, str(SCRIPT), context.url, str(width)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


@then(
    "the canvas draws one group card for the hook with its file count and "
    "tokens and opening it lists the loads with the repeated file once as times three"
)
def step_page(context):
    for width in (1280, 1920):
        seen = _page(context, width)
        if not seen:
            return
        assert len(seen["cards"]) == 1, seen
        card = seen["cards"][0]
        assert HOOK in card and "2 files" in card, card
        assert re.search(r"~\d", card), card
        assert len(seen["rows"]) == 2 and sorted(seen["rows"], key=len)[0].count("\u00d7") == 0, seen["rows"]
        assert any("\u00d73" in row for row in seen["rows"]), seen["rows"]


@then(
    "the same session where the hook fired silently names no hook and holds the same context "
    "and the same instruction-load tokens"
)
def step_same_totals(context):
    grouped = context.grouped_view
    env = {**os.environ, "HOME": str(context.bare_home), "USERPROFILE": str(context.bare_home)}
    from support import AILS_BIN  # behave puts features/ on sys.path

    proc = subprocess.Popen(  # pylint: disable=consider-using-with  # killed by the scenario cleanup
        [str(AILS_BIN), "xray", "--no-open"],
        cwd=str(context.bare_project),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    context.add_cleanup(proc.kill)
    watchdog = threading.Timer(60, proc.kill)
    watchdog.start()
    context.add_cleanup(watchdog.cancel)
    line = proc.stdout.readline()
    found = re.search(r"http://127\.0\.0\.1:\d+/", line)
    assert found, line
    bare = _view(found.group(0))
    assert not [g for g in _main_station(bare)["groups"] if g["hook"]], "a session with no firing named a hook"
    main = lambda view: next(node for node in view["nodes"] if node["id"] == "main")  # noqa: E731
    assert main(grouped)["detail"]["composition"] == main(bare)["detail"]["composition"], "the context differs"

    def tokens(view: dict) -> int:
        station = _main_station(view)
        kinds = {source["id"]: source["kind"] for source in view["sources"]}
        loose = sum(load["tokens_est"] or 0 for load in station["loads"] if kinds[load["source"]] == "instructions")
        return loose + sum(group["tokens_est"] for group in station["groups"])

    assert tokens(grouped) == tokens(bare) > 0, (tokens(grouped), tokens(bare))


@then("every compaction stripe's text ends inside its stripe at 1280 and at 1920 pixels")
def step_stripes(context):
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return
    script = Path(__file__).resolve().parents[1] / "xray_stripes.mjs"
    for width in (1280, 1920):
        done = subprocess.run(
            [node, str(script), context.url, str(width)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
            env={**os.environ, "CHROME_BIN": chrome, "XRAY_KEEP_FOLDS": "1"},
        )
        assert done.returncode == 0, done.stderr
        seen = json.loads(done.stdout.strip().splitlines()[-1])
        assert seen["ready"] and seen["stripes"], seen
        assert all(stripe["past"] <= 0 for stripe in seen["stripes"]), (width, seen["stripes"])
        assert any(stripe["clipped"] for stripe in seen["stripes"]), (
            width,
            "no stripe was long enough to be cut",
            seen,
        )
