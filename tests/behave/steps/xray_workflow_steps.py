"""Step definitions for the x-ray workflow node: a recorded Workflow session, the real `ails xray` and its page."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from behave import given, then  # type: ignore[import-untyped]
from steps.xray_steps import _get  # behave puts features/ on sys.path
from support import build_project

from reporails_cli.core.discovery.agent_discovery import claude_project_folder_name

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript" / "2.1.311-workflow"
SCRIPT = Path(__file__).resolve().parents[1] / "xray_workflow.mjs"
NAME = "release-check"


def _folder(context) -> Path:
    return context.home / ".claude" / "projects" / claude_project_folder_name(context.project)


@given("a project with a recorded Claude Code session that ran a Workflow of two phases")
def step_session(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    folder = _folder(context)
    folder.mkdir(parents=True)
    shutil.copytree(FIXTURE / "session", folder / "session")
    record = folder / "session" / "workflows" / "wf_test01.json"
    record.write_text(record.read_text(encoding="utf-8").replace("PLACEHOLDER-WORKFLOW", NAME), encoding="utf-8")
    text = (FIXTURE / "session.jsonl").read_text(encoding="utf-8")
    (folder / "session.jsonl").write_text(
        text.replace("/work/proj", json.dumps(str(context.project))[1:-1]), encoding="utf-8"
    )


def _second_record(context) -> Path:
    """Writes a well-formed second run record beside the first and returns the first run's record file."""
    workflows = _folder(context) / "session" / "workflows"
    first = workflows / "wf_test01.json"
    good = json.loads(first.read_text(encoding="utf-8")) | {
        "runId": "wf_second01",
        "workflowName": "second-check",
        "workflowProgress": [],
    }
    (workflows / "wf_second01.json").write_text(json.dumps(good), encoding="utf-8")
    return first


@given(
    "the session holds a second well-formed Workflow run record and the first run's record "
    "holds a status that is not text"
)
def step_bad_record(context):
    first = _second_record(context)
    first.write_text(json.dumps(json.loads(first.read_text(encoding="utf-8")) | {"status": 7}), encoding="utf-8")


@given("the session holds a second well-formed Workflow run record and the first run's record is cut off mid-write")
def step_cut_record(context):
    first = _second_record(context)
    first.write_text(first.read_text(encoding="utf-8")[:40], encoding="utf-8")


def _view(url: str) -> dict:
    status, page = _get(url)
    assert status == 200, status
    token = re.search(r'name="xray-token" content="([^"]+)"', page)
    assert token, "the page carries no launch token"
    status, body = _get(url + "view", token.group(1))
    assert status == 200, status
    return json.loads(body)


def _page(context, width: int = 1440) -> dict:
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
    "the view holds the workflow with its name, status, two agents, token "
    "total and one agent under each of its two phases"
)
def step_view(context):
    view = _view(context.url)
    (run,) = view["workflows"]
    assert (run["name"], run["status"], run["agent_count"], run["total_tokens"]) == (NAME, "completed", 2, 4200), run
    assert [p["title"] for p in run["phases"]] == ["Build", "Verify"], run["phases"]
    nodes = {node["id"] for node in view["nodes"]}
    assert [len(p["agents"]) for p in run["phases"]] == [1, 1], run["phases"]
    assert {a for p in run["phases"] for a in p["agents"]} <= nodes, "an agent of the run is not a node"
    assert run["refusal"] is None
    context.run_view = run


@then("the canvas draws the workflow node with those facts and opening it lists each phase with its agent")
def step_page(context):
    seen = _page(context)
    if not seen:
        return
    (card,) = seen["cards"]
    for want in (NAME, "completed", "2 agents", "Build", "Verify"):
        assert want in card, (want, card)
    assert re.search(r"~4\.2k", card), card
    kinds = [row.split("|")[0] for row in seen["phases"]]
    assert kinds == ["wf-phase", "wf-agent", "wf-phase", "wf-agent"], seen["phases"]


@then(
    "the view holds the second run as a readable node and the first as not readable with the reason, "
    "and the canvas still draws both nodes"
)
def step_unreadable(context):
    view = _view(context.url)
    runs = {run["run_id"]: run for run in view["workflows"]}
    assert set(runs) == {"wf_test01", "wf_second01"}, runs
    bad, good = runs["wf_test01"], runs["wf_second01"]
    assert (bad["status"], bad["status_text"]) == ("unreadable", "not readable"), bad
    assert bad["name"] is None and bad["total_tokens"] is None and bad["refusal"], bad
    assert [p["title"] for p in bad["phases"]] == ["Build", "Verify"], bad["phases"]
    assert (good["name"], good["status"], good["refusal"]) == ("second-check", "completed", None), good
    seen = _page(context)
    if not seen:
        return
    assert seen["ready"], "the page did not draw"
    assert len(seen["cards"]) == 2, seen["cards"]
    assert sum("not readable" in card for card in seen["cards"]) == 1, seen["cards"]
    assert sum("second-check" in card for card in seen["cards"]) == 1, seen["cards"]
