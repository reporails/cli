"""Step definitions for the x-ray page fixes: wording, counts, scope buttons, hint bar, late results and view fields."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from behave import given, then  # type: ignore[import-untyped]

SCRIPT = Path(__file__).resolve().parents[1] / "xray_fix.mjs"
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "xray"
UNRECORDED = "not recorded in this session"


def _drive(context, mode: str, args: dict | None = None) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    done = subprocess.run(
        [node, str(SCRIPT), context.url, mode, json.dumps(args or {})],
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


def _node(view: dict, node_id: str) -> dict:
    return next(n for n in view["nodes"] if n["id"] == node_id)


def _kind_flag(view: dict, kind: str, flag: str, value: bool) -> None:
    next(k for k in view["adapter"]["source_kinds"] if k["key"] == kind)[flag] = value


def _unrecorded_memory(view: dict) -> None:
    for s in view["sources"]:
        if s["kind"] == "memory":
            s.update(availability="unrecorded", had_by=[], cost_usd_est=None)
    row = next(f for f in view["funnel"] if f["kind"] == "memory")
    row.update(loaded=None, used=None)
    detail = _node(view, "a1")["detail"]
    detail.update(back_tokens_est=None, back_ratio=None)


def _instructions_are_memory(view: dict) -> None:
    for k in view["adapter"]["source_kinds"]:
        k["instructions"] = k["key"] == "memory"


def _memory_on_the_spine(view: dict) -> None:
    _kind_flag(view, "hook", "spine", False)
    _kind_flag(view, "memory", "spine", True)


def _late_load(view: dict) -> None:
    station = next(s for s in view["stations"] if s["node"] == "a1")
    next(ld for ld in station["loads"] if ld["source"] == "CLAUDE.md")["t"] = 150.0


def _over(view: dict) -> None:
    comp = _node(view, "main")["detail"]["composition"]
    # A reply row ends with its over-estimate flag, then whether it was measured.
    comp["replies"][comp["peak"]][-2] = True


def _no_replies(view: dict) -> None:
    _node(view, "a1")["detail"]["peak"] = None


def _line_break_id(view: dict) -> None:
    changed = json.loads(json.dumps(view).replace(".claude/rules/rules-engine.md", ".claude/rules/rules-\\nengine.md"))
    view.clear()
    view.update(changed)


CHANGES = {
    "the first subagent has no replies": _no_replies,
    "a source id holds a line break": _line_break_id,
    "its memory was not recorded": _unrecorded_memory,
    "only memory files count as instructions": _instructions_are_memory,
    "memory loads stay on the spine and hook loads do not": _memory_on_the_spine,
    "the first subagent loaded CLAUDE.md late": _late_load,
    "the main agent's estimates overshoot": _over,
}


@given('the bundled page is served over the "{name}" fixture view changed so {change}')
def step_serve_changed(context, name, change):
    view = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    CHANGES[change](view)
    path = Path("/tmp") / f"xray_fix_{os.getpid()}_{abs(hash(change))}.json"
    path.write_text(json.dumps(view), encoding="utf-8")
    context.add_cleanup(lambda: path.unlink(missing_ok=True))
    context.execute_steps(f'Given the bundled page is served over the "{str(path)[:-5]}" fixture view')


@given("the server refuses the call route")
def step_call_refused(context):
    context.call_refused = True


@given("the server has not recorded the call's result yet")
def step_no_result(context):
    context.call_result = False


@then(
    "the Sources table prints each count of findings, a dash for none, "
    'and "not visible" for a built-in item the transcript hides'
)
def step_findings_column(context):
    seen = _drive(context, "sources_table")
    if seen is None:
        return
    view = context.fixture
    assert "[object Object]" not in seen["all"], seen["all"]
    rows = {r["id"]: r for r in seen["rows"]}
    counts = {s["id"]: (s["findings"] or {}).get("count", 0) for s in view["sources"]}
    assert any(counts.values()) and not all(counts.values())
    for source_id, count in counts.items():
        row = rows[source_id]
        assert row["finds"] == (str(count) if count else "\u2013"), (source_id, row)
        assert ("tb-find" in row["findsClass"]) == bool(count), (source_id, row)
    hidden = [b for b in view["builtin"] if b["visible"] == "hidden"]
    assert hidden, "the fixture has no hidden built-in item"
    for b in view["builtin"]:
        assert ("not visible" in rows[f"builtin:{b['key']}"]["who"]) == (b["visible"] == "hidden"), b


@then("the Sources table says the memory files were not recorded in this session, not that they were never loaded")
def step_unrecorded_table(context):
    seen = _drive(context, "unrecorded")
    if seen is None:
        return
    assert seen["header"] == {"used": "\u2013", "total": "/56", "title": seen["header"]["title"]}, seen["header"]
    assert UNRECORDED in seen["header"]["title"], seen["header"]
    assert seen["rows"] and all(r.startswith(UNRECORDED) for r in seen["rows"]), seen["rows"]
    assert seen["table"] and all(r == UNRECORDED for r in seen["table"]), seen["table"]
    assert UNRECORDED in seen["peek"] and "never loaded" not in seen["peek"], seen["peek"]


@then("the subagent's Output line says its hand-back size is not known and shows no ratio")
def step_unknown_back(context):
    seen = _drive(context, "unrecorded")
    if seen is None:
        return
    assert "not known" in seen["output"] and "smaller" not in seen["output"], seen["output"]


@then("a call's details list the files of the kinds the view flags as instructions")
def step_call_instructions(context):
    view = context.fixture
    flagged = {k["key"] for k in view["adapter"]["source_kinds"] if k.get("instructions")}
    by_id = {s["id"]: s for s in view["sources"]}
    calls = sorted(((c["t"], t["node"], c) for t in view["track"] for c in t["calls"]), key=lambda r: r[0])[:150]
    stations = {s["node"]: s for s in view["stations"]}

    def in_context(when: float, node_id: str) -> list[str]:
        want: list[str] = []
        for load in stations[node_id]["loads"]:
            source = by_id.get(load["source"])
            if (
                source
                and (load["t"] is None or load["t"] <= when)
                and source["kind"] in flagged
                and source["id"] not in want
            ):
                want.append(source["id"])
        return want

    index = max(i for i, r in enumerate(calls) if in_context(r[0], r[1]))
    when, node_id, call = calls[index]
    want = in_context(when, node_id)
    seen = _drive(context, "calls_instr", {"id": call["use_id"], "index": index})
    if seen is None:
        return
    assert want, "the chosen call has no flagged file in context"
    assert seen["sources"] == want, (seen["sources"], want)
    counts = [(by_id[w]["findings"] or {}).get("count", 0) for w in want]
    assert seen["finds"] == [f"{n} findings" if n else "" for n in counts], seen["finds"]


@then(
    "the Tool calls tab shows the agent summary beside the table, no scope buttons and a hint bar only on the Graph tab"
)
def step_solo(context):
    seen = _drive(context, "solo")
    if seen is None:
        return
    node = context.fixture["nodes"][0]
    assert seen["tab"] == "graph", seen
    assert seen["scopeButtons"] == 0, "a session with one agent shows scope buttons"
    assert seen["hintHidden"] is True and seen["hintSources"] is True and seen["hintGraph"] is False, seen
    labels = ["Peak context", "Est. cost"]
    for tiles in (seen["tiles"], seen["tilesSources"]):
        assert [t[: len(x)] for t, x in zip(tiles, labels, strict=True)] == labels, tiles
        assert not any("this agent" in t for t in tiles), "one agent is not 'this agent'"
    assert seen["context"] and seen["context"].endswith("at peak"), seen
    assert f"${node['detail']['cost']['total_usd']:.2f}" in seen["tiles"][1], seen["tiles"]


@then("the scope button of a long agent name is cut with an ellipsis and carries the full name")
def step_scope_name(context):
    seen = _drive(context, "scope_name", {"chain": ["main", "a2"]})
    if seen is None:
        return
    name = _node(context.fixture, "a2")["name"]
    button = seen["button"]
    assert button["title"] == f"{name} only", button
    assert button["truncated"] is True and button["width"] < 320, button


@then('"Show all" closes when a filter changes')
def step_show_all(context):
    seen = _drive(context, "show_all")
    if seen is None:
        return
    assert seen["start"].startswith("Show all"), seen
    assert seen["opened"].startswith("Show first"), seen
    assert seen.get("afterFilter", "").startswith("Show all"), seen


@then("a call opened before its result landed shows the result after the view changes")
def step_late_result(context):
    seen = _drive(context, "late_result")
    if seen is None:
        return
    assert "No result recorded" in seen["before"], seen["before"]
    assert "result of toolu_" in seen["after"], seen["after"]


@then("the page opens on the Graph tab and the session picked in the header opens on it too")
def step_default_tab(context):
    seen = _drive(context, "default_tab")
    if seen is None:
        return
    assert seen["first"] == "graph", seen
    assert seen["picked"] == "?session=sess-bbb", seen
    assert seen["later"] == "graph", seen


@then("the main agent's cost tile and details list the session total, the subagents' share and the costliest subagents")
def step_cost(context):
    seen = _drive(context, "cost")
    if seen is None:
        return
    cost = context.fixture["session_cost"]
    main = next(usd for node_id, usd in cost["by_agent"] if node_id == "main")
    assert "Est. cost · this agent" in seen["tile"] and f"Session ~${cost['total_usd']:.2f}" in seen["tile"], seen[
        "tile"
    ]
    assert f"~${cost['total_usd'] - main:.2f}" in seen["tile"], seen["tile"]
    assert "Session" in seen["panel"] and f"~${cost['total_usd']:.2f}" in seen["panel"], seen["panel"]
    want = [(node_id, usd) for node_id, usd in cost["by_agent"] if node_id != "main"][:5]
    assert [r["id"] for r in seen["list"]] == [w[0] for w in want], seen["list"]
    for row, (_, usd) in zip(seen["list"], want, strict=True):
        assert row["text"].endswith(f"~${usd:.2f}"), row


@then("the details word the cache figures, the work size, the load time and the exact total as the numbers mean")
def step_wording(context):
    seen = _drive(context, "wording")
    if seen is None:
        return
    view = context.fixture
    assert seen["total"].endswith(" at peak") and not seen["total"].startswith("~"), seen["total"]
    assert "Read from cache at this turn" in seen["peak"], seen["peak"]
    assert "Read from cache across all replies" in seen["cost"], seen["cost"]
    assert seen["roles"] == ["Index", "Read on demand"], seen["roles"]
    late = next(r for r in seen["loadedIn"] if r["id"] == "a1")
    assert late["text"].endswith("2:30"), late
    detail = _node(view, "a1")["detail"]
    work = (detail["peak"] - detail["context_start"] + 500) // 1000
    assert f"{work}k of work" in seen["output"], seen["output"]
    assert "Result after" in seen["head"] and "Took" not in seen["head"], seen["head"]
    assert "Result after" in seen["kv"] and "Took" not in seen["kv"], seen["kv"]
    assert seen["k1"] == ["10M", "1M", "1.5M", "10k", "1.23M"], seen["k1"]


@then("the peak details say the estimates overshoot and no percentage passes 100")
def step_over(context):
    seen = _drive(context, "over")
    if seen is None:
        return
    assert "add up to more than the exact total" in seen["peak"], seen["peak"]
    assert seen["pcts"] and all(int(p.rstrip("%")) <= 100 for p in seen["pcts"]), seen["pcts"]


@then("only the memory loads and the hook firings are stations on the spine")
def step_spine_flag(context):
    seen = _drive(context, "canvas")
    if seen is None:
        return
    view = context.fixture
    memory = {s["id"] for s in view["sources"] if s["kind"] == "memory"}
    assert memory & set(seen["stations"]), seen["stations"]
    hooks = {s["id"] for s in view["sources"] if s["kind"] == "hook"}
    firings = {h["source"] for st in view["stations"] for h in st.get("hooks", [])}
    assert (set(seen["stations"]) & hooks) <= firings, seen["stations"]


@then("the link to Tool calls opens it for the agent on screen only")
def step_calls_link(context):
    seen = _drive(context, "canvas")
    if seen is None:
        return
    view = context.fixture
    assert seen["link"] == {"tab": "calls", "scope": "one"}, seen["link"]
    assert seen["tab"] == "calls" and seen["scopeOne"] == "true", seen
    mine = len(next(t for t in view["track"] if t["node"] == "main")["calls"])
    total = sum(len(t["calls"]) for t in view["track"])
    assert seen["summary"].startswith(f"{mine} of {total} calls"), seen["summary"]


@then("the subagent's Output line says the size of its work is not known and never reads 0 of work")
def step_no_peak(context):
    seen = _drive(context, "unrecorded")
    if seen is None:
        return
    assert "0 of work" not in seen["output"] and "work is not known" in seen["output"], seen["output"]
