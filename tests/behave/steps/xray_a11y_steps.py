"""Step definitions for the x-ray page's accessibility: focus, keyboard, contrast, target size and reflow."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from behave import then  # type: ignore[import-untyped]

SCRIPT = Path(__file__).resolve().parents[1] / "xray_a11y.mjs"
ROWS_SHOWN = 150  # the Tool calls table draws this many rows until "Show all"
MIN_TARGET = 24


def _a11y(context, mode: str, width: int = 1440) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    done = subprocess.run(
        [node, str(SCRIPT), context.url, mode, str(width)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
        check=False,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout.strip().splitlines()[-1])
    assert seen["ready"], f"the page did not draw the fixture in mode {mode}"
    return seen


@then("tabbing onto a canvas source node keeps focus on it after the canvas redraws for hover and focus")
def step_canvas_focus(context):
    seen = _a11y(context, "canvas-focus")
    if seen is None:
        return
    assert seen["tabbed"], "Tab never reached a canvas source node"
    node = seen["tabbed"]["source"]
    for where in ("afterFocus", "afterHover", "afterLeave"):
        got = seen[where]
        assert got["source"] == node and "snode" in got["cls"].split(), (where, got, node)


@then("Enter on an eye toggle and on a group header keeps focus on that control")
def step_toggles(context):
    seen = _a11y(context, "toggles")
    if seen is None:
        return
    eye = seen["eye"]
    assert eye["before"]["eye"] and eye["after"]["eye"] == eye["before"]["eye"], eye
    assert eye["pressed"] == "false", eye  # the Enter did press the toggle
    group = seen["group"]
    assert group["before"]["group"] and group["after"]["group"] == group["before"]["group"], group
    assert group["after"]["expanded"] != group["before"]["expanded"], group  # the Enter did toggle the group
    assert seen["groupSpace"]["group"] == group["before"]["group"], seen["groupSpace"]


@then(
    "Enter on a canvas source node opens details with one click, the canvas is inert, "
    "and Escape returns focus to that node"
)
def step_opener(context):
    seen = _a11y(context, "opener")
    if seen is None:
        return
    assert seen["opener"], "Tab never reached a canvas source node"
    assert seen["clicks"] == 1, seen["clicks"]  # a native button must not click twice on Enter
    assert seen["open"]["closePeek"], seen["open"]
    assert seen["inert"] is True, "the canvas stays reachable behind the open details"
    assert seen["tabsInCanvas"] == 0, f"Tab from the details reached the canvas {seen['tabsInCanvas']} times"
    after = seen["afterEsc"]
    assert after["inCanvas"] and not after["inSources"], after
    assert after["source"] == seen["opener"]["source"], (after, seen["opener"])


@then("Space on an agent card selects it and its accessible name carries its slot summary")
def step_space(context):
    seen = _a11y(context, "space")
    if seen is None:
        return
    assert seen["sel"] == seen["node"], seen
    assert seen["chips"], seen
    for label in seen["chips"]:
        assert label in seen["name"], (label, seen["name"])


@then(
    "the Tool calls table is a grid with row counts and indexes, arrow keys walk its rows across window swaps, "
    "and its summary is written only on change"
)
def step_table(context):
    seen = _a11y(context, "table")
    if seen is None:
        return
    total = json.dumps(seen["all"])
    assert seen["all"]["role"] in ("table", "grid"), total
    assert seen["all"]["heads"] >= 5, total
    assert int(seen["all"]["rowcount"]) == min(ROWS_SHOWN, int(seen["all"]["summary"].split(" of ")[0])), total
    failed = seen["failed"]
    assert int(failed["rowcount"]) == int(failed["summary"].split(" of ")[0]) < ROWS_SHOWN, failed
    for fixture in (seen["all"], failed):
        assert fixture["rows"] and all(r[0] == "row" and r[1] for r in fixture["rows"]), fixture["rows"][:3]
    walked = [int(i) for i in seen["walked"]]
    assert walked == list(range(walked[0], walked[0] + 31)), walked  # focus followed the rows, past the window swap
    assert seen["windowStart"] > 1, "the walk did not swap the drawn window"
    assert seen["statusWrites"] == 2, seen["statusWrites"]  # two filter changes, two summaries, none on a redraw alone


@then(
    "no visible text on the Graph, Tool calls and Sources tabs falls under 4.5 to 1 contrast "
    "in plain, selected and dimmed states"
)
def step_contrast(context):
    seen = _a11y(context, "contrast")
    if seen is None:
        return
    assert seen["dimCount"] > 0, "the hover did not dim any card, node or station"
    for where in ("plain", "selected", "dimmed", "calls", "sources"):
        assert seen[where]["seen"] > 20, (where, seen[where]["seen"])
        assert seen[where]["bad"] == [], (where, seen[where]["bad"][:8])


@then("segment and session switcher borders and the selected tab and segment indicators reach 3 to 1")
def step_borders(context):
    seen = _a11y(context, "borders")
    if seen is None:
        return
    for item in seen["borders"]:
        assert item["ratio"] >= 3, item


@then("at a 580 pixel graph column every canvas text renders at least 10.5 pixels")
def step_scale_text(context):
    seen = _a11y(context, "scale-text", 1220)
    if seen is None:
        return
    assert seen["col"] < 580 and seen["zoom"] <= 0.72, seen  # the narrowest zoom step is the one under test
    assert seen["small"]["seen"] > 20, seen["small"]["seen"]
    assert seen["small"]["bad"] == [], seen["small"]["bad"][:8]


@then("every rail marker and station dot measures at least 24 pixels each way")
def step_hit_areas(context):
    seen = _a11y(context, "hit-areas")
    if seen is None:
        return
    assert any("rail-mark" in t["cls"] for t in seen["targets"]), seen["targets"]
    assert any("station" in t["cls"] for t in seen["targets"]), "the fixture draws no station dot to measure"
    for t in seen["targets"]:
        assert t["w"] >= MIN_TARGET and t["h"] >= MIN_TARGET, t


@then("at 700 pixels the page has one column and no sideways scroll")
def step_reflow(context):
    seen = _a11y(context, "reflow", 700)
    if seen is None:
        return
    lay = seen["layout"]
    assert lay["scrollWidth"] <= lay["innerWidth"], lay
    assert lay["cols"] == 1 and lay["graphview"] == 1, lay
