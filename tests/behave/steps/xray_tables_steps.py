"""Step definitions for the x-ray Tool calls and Sources tables."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from behave import given, then  # type: ignore[import-untyped]

SCRIPT = Path(__file__).resolve().parents[1] / "xray_tables.mjs"
SUMMARY = re.compile(r"^(\d+) of (\d+) calls · (\d+) failed$")


def _drive(context, mode: str, chains: dict[str, list[str]] | None = None) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    done = subprocess.run(
        [node, str(SCRIPT), context.url, mode, json.dumps(chains or {})],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout.strip().splitlines()[-1])
    assert seen["ready"], f"the page did not draw the fixture in mode {mode}"
    return seen


def _chains(view: dict) -> dict[str, list[str]]:
    parent = {n["id"]: n["parent"] for n in view["nodes"]}
    out: dict[str, list[str]] = {}
    for node_id in parent:
        chain, at = [], node_id
        while at:
            chain.insert(0, at)
            at = parent[at]
        out[node_id] = chain
    return out


def _calls_by_node(view: dict) -> dict[str, list[dict]]:
    return {t["node"]: t["calls"] for t in view["track"]}


def _subtree(view: dict, node_id: str) -> set[str]:
    kids = {n["id"]: n["children"] for n in view["nodes"]}
    out, todo = set(), [node_id]
    while todo:
        at = todo.pop()
        out.add(at)
        todo.extend(kids[at])
    return out


def _summary(text: str) -> tuple[int, int, int]:
    m = SUMMARY.match(text)
    assert m, f"summary line is not 'N of M calls · F failed': {text!r}"
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


@then("the Tool calls tab counts match the view for every scope and the failed-only filter")
def step_counts(context):
    view = context.fixture
    seen = _drive(context, "counts", _chains(view))
    if seen is None:
        return
    by_node = _calls_by_node(view)
    every = [c for calls in by_node.values() for c in calls]
    failed = sum(1 for c in every if c["failed"])
    assert _summary(seen["summary"]) == (len(every), len(every), failed), seen["summary"]
    assert seen["strip"]["canvases"] == 1 and seen["strip"]["tickEls"] <= 12, seen["strip"]
    assert seen["failedPressed"] == "true"
    assert _summary(seen["failedOnly"]) == (failed, len(every), failed), seen["failedOnly"]
    assert seen["failedRows"] == failed, "the failed-only table does not list the failed calls"
    for node_id, got in seen["scopes"].items():
        node = next(n for n in view["nodes"] if n["id"] == node_id)
        assert ("sub" in got["have"]) == bool(node["children"]), (node_id, got["have"])
        one = by_node.get(node_id, [])
        assert _summary(got["one"])[0] == len(one) and got["oneRows"] == len(one), (node_id, got)
        assert _summary(got["all"])[0] == len(every) and got["allRows"] == len(every), (node_id, got)
        if "sub" in got["have"]:
            ids = _subtree(view, node_id)
            want = sum(len(by_node.get(i, [])) for i in ids)
            assert _summary(got["sub"])[0] == want and got["subRows"] == want, (node_id, got, want)
        # Failed-only counts are fixed by the data; the one-agent scope lists exactly its failures.
        assert _summary(got["one"])[2] == sum(1 for c in one if c["failed"]), (node_id, got)


@then("for every agent and tool the Tool calls table with that scope and tool has the inspector's calls and failures")
def step_tools(context):
    view = context.fixture
    seen = _drive(context, "tools", _chains(view))
    if seen is None:
        return
    checked = 0
    for node in view["nodes"]:
        rows = seen["rows"][node["id"]]
        for tool in node["tools"]:
            if tool["calls"] == 0:
                continue
            got = rows.get(tool["tool"])
            assert got, f"{node['id']}: tool {tool['tool']} has no filter button"
            n, _, f = _summary(got["s"])
            assert (n, f) == (tool["calls"], tool["failed"]), (node["id"], tool, got)
            assert _summary(got["failed"])[0] == tool["failed"], (node["id"], tool, got)
            checked += 1
    assert checked > 10, f"only {checked} agent and tool pairs were compared"


@then("a click on a call row fills the side panel with the call's input and result from the server")
def step_peek(context):
    seen = _drive(context, "peek")
    if seen is None:
        return
    assert "result of toolu_" in seen["panel"] and "command" in seen["panel"], seen["panel"]
    assert seen["overlay"] is False, "the Tool calls tab opened the graph overlay"
    assert seen["showInGraph"] is True
    assert seen["opened"].startswith("call:toolu_"), seen["opened"]
    assert seen["instr"] >= 1, "no instruction file is listed for the call"


def _asked_for_commands(context) -> list[str]:
    return [r for r in context.handler.requests if r.startswith("/call")]


@then("a shell call's row shows its command and no more commands are requested than rows are drawn")
def step_shell_summary(context):
    seen = _drive(context, "summary")
    if seen is None:
        return
    row = next((r for r in seen["failedRows"] if r["peek"] == "call:toolu_fail0"), None)
    assert row and row["summary"] == "npm test -- --runInBand", seen["failedRows"]
    asked = _asked_for_commands(context)
    assert len(asked) == len(set(asked)), asked
    # Drawn rows before the filter, plus the failed rows drawn after it.
    assert len(asked) <= seen["drawn"] + len(seen["failedRows"]), (len(asked), seen["drawn"])


@then("a running call's command is requested once across view versions and once more after its result lands")
def step_running_call(context):
    # Two views with the call running, then the view that shows its result: one request each side of the landing.
    seen = _drive(context, "running_call")
    if seen is None:
        return
    asked = [r for r in _asked_for_commands(context) if "id=toolu_main_0" in r]
    assert len(asked) == 2, asked


@then("no more commands are requested than rows are drawn")
def step_commands_for_drawn_rows(context):
    seen = _drive(context, "summary_draw")
    if seen is None:
        return
    asked = _asked_for_commands(context)
    assert seen["drawn"] > 0 and len(asked) <= seen["drawn"], (len(asked), seen["drawn"])
    assert len(asked) == len(set(asked)), asked


@given("the bundled page is served over a view holding {n:d} calls")
def step_big_view(context, n):
    source = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "xray" / "view_sample.json").read_text())
    first = source["track"][0]
    base = list(first["calls"])
    first["calls"] = [{**base[i % len(base)], "t": 7300.0 + i / 100, "use_id": f"toolu_big_{i}"} for i in range(n)]
    path = Path(context.tmpdir if hasattr(context, "tmpdir") else "/tmp") / f"big_{os.getpid()}.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    context.add_cleanup(lambda: path.unlink(missing_ok=True))
    context.execute_steps(f'Given the bundled page is served over the "{str(path)[:-5]}" fixture view')
    context.big_last = f"call:toolu_big_{n - 1}"


@then("fewer than 200 rows are in the page and scrolling the table shows the last call")
def step_virtual(context):
    seen = _drive(context, "virtual")
    if seen is None:
        return
    assert 0 < seen["rowsFirst"] < 200 and 0 < seen["rowsAll"] < 200 and 0 < seen["rowsEnd"] < 200, seen
    assert seen["height"] >= 2000 * 34, seen["height"]
    assert seen["lastPeek"] == context.big_last, seen["lastPeek"]


@then("the Sources table lists every source and every built-in item")
def step_sources(context):
    view = context.fixture
    seen = _drive(context, "sources")
    if seen is None:
        return
    total = len(view["sources"]) + len(view["builtin"])
    assert seen["height"] == total * 36, (seen["height"], total)
    assert len(seen["rows"]) == total, (len(seen["rows"]), total)
    assert {r["source"] for r in seen["rows"] if r["source"]} == {s["id"] for s in view["sources"]}
    assert {r["peek"] for r in seen["rows"] if r["peek"]} == {f"builtin:{b['key']}" for b in view["builtin"]}
    assert any("agents" in r["text"] or "never" in r["text"] for r in seen["rows"])
