"""Step definitions for the x-ray canvas: source nodes, hooks, layers, group labels, the jump rail, the side track."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from behave import then  # type: ignore[import-untyped]

SCRIPT = Path(__file__).resolve().parents[1] / "xray_canvas.mjs"

# The modes that look at the folds themselves; every other mode gets each fold opened as it draws.
FOLD_MODES = {"folds", "fold-key"}


def _canvas(context, mode: str, *args: str, width: int = 1440) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    done = subprocess.run(
        [node, str(SCRIPT), context.url, mode, str(width), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
        env={**os.environ, "CHROME_BIN": chrome, **({"XRAY_KEEP_FOLDS": "1"} if mode in FOLD_MODES else {})},
    )
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout.strip().splitlines()[-1])
    assert seen["ready"], f"the page did not draw the fixture in mode {mode}"
    return seen


def _main(context) -> dict:
    return next(n for n in context.fixture["nodes"] if n["id"] == "main")


def _station(context) -> dict:
    return next(s for s in context.fixture["stations"] if s["node"] == "main")


def _first_loads(context) -> dict[str, float]:
    """Source id -> the first load time among the main agent's loads of every kind but hooks (hooks carry an event)."""
    station = _station(context)
    first: dict[str, float] = {}
    for load in station["loads"]:
        if load["event"] is not None:
            continue
        t = load["t"] if load["t"] is not None else _main(context)["start"]
        first[load["source"]] = min(t, first.get(load["source"], t))
    for cluster in station["mcp"]:
        first.setdefault(cluster["server"], cluster["first"])
    return first


@then(
    "every agent card is right of the spine, every source node left of it, each source has one node at its first load "
    "and no legend is drawn"
)
def step_sides(context):
    seen = _canvas(context, "layout")
    if seen is None:
        return
    spine = seen["spine"]
    assert seen["cards"] and seen["nodes"], seen
    assert all(c["left"] > spine for c in seen["cards"] + seen["groupCards"]), seen["cards"]
    assert all(n["right"] < spine for n in seen["nodes"]), seen["nodes"]
    expected = _first_loads(context)
    assert sorted(seen["nodeIds"]) == sorted(expected), (seen["nodeIds"], sorted(expected))
    assert sorted(seen["edges"]) == sorted(expected) and seen["arrows"] == len(expected), seen
    assert seen["legend"] is False and seen["link"] == "open in Tool calls →", seen
    for source, text in seen["nodeText"].items():
        if source.startswith("mcp:"):
            continue
        assert "↓" in text and f"{int(expected[source]) // 60}:{int(expected[source]) % 60:02d}" in text, (source, text)


@then("each MCP server is one node with as many round-trip edges as call clusters and its call count")
def step_mcp(context):
    seen = _canvas(context, "layout")
    if seen is None:
        return
    clusters: dict[str, list[dict]] = {}
    for cluster in _station(context)["mcp"]:
        clusters.setdefault(cluster["server"], []).append(cluster)
    assert clusters, "the fixture has no MCP calls"
    for server, group in clusters.items():
        assert seen["nodeIds"].count(server) == 1, (server, seen["nodeIds"])
        assert seen["trips"].count(server) == len(group), (server, seen["trips"])
        assert f"⇄ {sum(c['calls'] for c in group)} calls" in seen["nodeText"][server], seen["nodeText"][server]


@then("hook loads and stretches are stations on the spine and the side track draws one path per tracked category")
def step_hooks_track(context):
    seen = _canvas(context, "layout")
    if seen is None:
        return
    station = _station(context)
    hook_loads = [load for load in station["loads"] if load["event"] is not None]
    assert hook_loads or station["hooks"], "the fixture has no hooks"
    assert seen["stations"], seen
    assert seen["spineStations"] >= 1, seen  # a pill that would cover a card or node sits beside the spine instead
    assert not any(s["source"] in seen["nodeIds"] for s in seen["stations"]), seen
    stretch = [s for s in seen["stations"] if "\u2193\u00d7" in s["text"]]
    assert len(stretch) == len(station["hooks"]), seen["stations"]
    tracked = [c["key"] for c in context.fixture["adapter"]["categories"] if c["track"]]
    assert seen["trackPaths"] == tracked, (seen["trackPaths"], tracked)
    assert seen["trackDivs"] == 0, "a tick is drawn as its own element"


@then("hiding the agent kind leaves no subagent card, group or arch and the main agent, spine and source nodes stay")
def step_eye_agents(context):
    kind = next(k["key"] for k in context.fixture["adapter"]["source_kinds"] if k["definitions"])
    seen = _canvas(context, "eye", kind)
    if seen is None:
        return
    before, after = seen["before"], seen["after"]
    assert before["cards"] > 0 and before["groups"] > 0 and before["arches"] > 0, before
    assert after["cards"] == 0 and after["groups"] == 0 and after["arches"] == 0, after
    assert after["top"] == 1 and after["spine"] == 1 and after["nodes"] == before["nodes"], (before, after)
    assert seen["again"] == before, seen


@then("a collapsed group holding the selected agent shows a solid border and its name instead of in parallel")
def step_group_selected(context):
    main = _main(context)
    burst = next(b for b in main["bursts"] if len(b["members"]) >= 2)
    start = {n["id"]: n["start"] for n in context.fixture["nodes"]}
    key = f"main:{min(burst['members'], key=start.__getitem__)}"
    member = burst["members"][-1]
    name = next(n["name"] for n in context.fixture["nodes"] if n["id"] == member)
    seen = _canvas(context, "collapsed", key, member)
    if seen is None:
        return
    assert seen["card"] is not None, seen
    assert f"● {name}" in seen["card"]["text"] and "in parallel" not in seen["card"]["text"], seen["card"]
    assert seen["card"]["border"] == "solid", seen["card"]
    assert all("in parallel" in text for text in seen["plain"]), seen["plain"]


@then(
    "the rail holds one marker per fan-out group and failure run plus the end "
    "and clicking the end marker scrolls the graph to it"
)
def step_rail(context):
    seen = _canvas(context, "rail")
    if seen is None:
        return
    main = _main(context)
    groups = [b for b in main["bursts"] if len(b["members"]) >= 2]
    runs = next(t for t in context.fixture["track"] if t["node"] == "main")["failure_runs"]
    kinds = [m["kind"] for m in seen["marks"]]
    assert kinds.count("fan") == len(groups) and kinds.count("fail") == len(runs) and kinds.count("end") == 1, kinds
    assert all(m["label"] for m in seen["marks"]), seen["marks"]
    assert seen["density"] == 48 and seen["railWidth"] == 22, seen
    after = seen["after"]
    assert after["scrollY"] > seen["before"], seen
    assert 0 <= after["y"] <= after["vh"], after  # the end of the page may leave the anchor below the middle


@then("every no-activity label sits clear of the cards, pills, spine and side track in its stripe")
def step_break_labels(context):
    seen = _canvas(context, "breaks")
    if seen is None:
        return
    assert len(seen["labels"]) >= 2, seen["labels"]
    for label in seen["labels"]:
        assert not label["hits"], label


def _cuts(context) -> list[dict]:
    return _station(context)["compactions"]


def _seg(context, t: float) -> int:
    return sum(1 for c in _cuts(context) if c["t"] <= t)


def _fold_counts(context, seg: int) -> tuple[int, int]:
    """The loads and the subagents the view holds for a segment, from the view's own times."""
    start = _main(context)["start"]
    loads = sum(
        1 for load in _station(context)["loads"] if _seg(context, load["t"] if load["t"] is not None else start) == seg
    )
    kids = sum(1 for n in context.fixture["nodes"] if n["parent"] == "main" and _seg(context, n["start"]) == seg)
    return loads, kids


@then("the segments before the newest compaction are folded bands and the newest segment is drawn open")
def step_folds_default(context):
    seen = _canvas(context, "folds")
    if seen is None:
        return
    last = len(_cuts(context))  # the segments are numbered 0..last, and `last` is the newest
    folds = seen["before"]["folds"]
    assert [f["group"] for f in folds] == [f"fold:main:{i}" for i in range(last)], folds
    assert all(f["expanded"] == "false" and f["tag"] == "BUTTON" for f in folds), folds
    assert not any(c.endswith(f":{last}") for c in seen["before"]["closers"]), seen["before"]["closers"]
    assert len(seen["before"]["stripes"]) == last, seen["before"]["stripes"]


@then("picking an agent launched in the first segment opens that segment and leaves the others folded")
def step_folds_pick(context):
    first = next(n["id"] for n in context.fixture["nodes"] if n["parent"] == "main" and _seg(context, n["start"]) == 0)
    seen = _canvas(context, "folds", first)
    if seen is None:
        return
    groups = [f["group"] for f in seen["before"]["folds"]]
    assert "fold:main:0" not in groups, groups
    assert "fold:main:1" in groups, groups
    assert seen["before"]["closers"] == ["fold:main:0"], seen["before"]["closers"]


@then("each folded segment shows the loads, agents and context before and after that the view holds")
def step_folds_numbers(context):
    seen = _canvas(context, "folds")
    if seen is None:
        return
    assert seen["before"]["folds"], "no folded segment drawn"
    for i, fold in enumerate(seen["before"]["folds"]):
        loads, kids = _fold_counts(context, i)
        cut = _cuts(context)[i]
        assert (fold["loads"], fold["agents"]) == (loads, kids), (fold, loads, kids)
        assert (fold["before"], fold["after"]) == (cut["before"], cut["after"]), fold
        assert f"{loads} load" in fold["text"] and f"{kids} agent" in fold["text"], fold["text"]
        assert f"{cut['before'] // 1000}k → {cut['after'] // 1000}k" in fold["text"], fold["text"]


@then("each stripe closing a folded segment lists the files that came back and the files that did not")
def step_folds_stripe(context):
    seen = _canvas(context, "folds")
    if seen is None:
        return
    labels = {s["id"]: s["label"] for s in context.fixture["sources"]}
    stripes = seen["before"]["stripes"]
    assert seen["before"]["folds"], "no folded segment drawn"
    for i in range(len(seen["before"]["folds"])):
        files = _cuts(context)[i]["files"]
        back = [
            labels.get(f["source"], f["source"]) for f in files if f["state"] in {"reloaded", "restored", "pending"}
        ]
        gone = [labels.get(f["source"], f["source"]) for f in files if f["state"] in {"named", "summarized"}]
        assert back and gone, files
        stripe = stripes[i]
        assert stripe["back"].split("\n") == back and stripe["notBack"].split("\n") == gone, (stripe, back, gone)
        assert all(name in stripe["text"] for name in back + gone), stripe["text"]


@then("clicking a folded segment opens it, keeps every compaction's sizes and lengthens the canvas")
def step_folds_open(context):
    seen = _canvas(context, "folds", "open")
    if seen is None:
        return
    before, after = seen["before"], seen["after"]
    assert before["folds"], "no folded segment drawn"
    assert len(after["folds"]) == len(before["folds"]) - 1, (before["folds"], after["folds"])
    assert after["closers"] == ["fold:main:0"], after["closers"]
    assert after["height"] > before["height"], (before["height"], after["height"])

    def sizes(snap):
        return [re.findall(r"\d+k → \d+k", s["text"]) for s in snap["stripes"]]

    assert sizes(before) == sizes(after), (sizes(before), sizes(after))


@then("picking a call that ran in the first segment opens that segment and leaves the others folded")
def step_folds_call(context):
    calls = next(t for t in context.fixture["track"] if t["node"] == "main")["calls"]
    call = next(c for c in calls if _seg(context, c["t"]) == 0)
    seen = _canvas(context, "folds", f"call:{call['use_id']}")
    if seen is None:
        return
    groups = [f["group"] for f in seen["before"]["folds"]]
    assert groups == ["fold:main:1", "fold:main:2"], groups
    assert seen["before"]["closers"] == ["fold:main:0"], seen["before"]["closers"]
