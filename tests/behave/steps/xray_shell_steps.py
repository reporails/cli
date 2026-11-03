"""Step definitions for the x-ray page's shell: tabs, hint bar, details frame, layout, type size and contrast."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from behave import then  # type: ignore[import-untyped]

SCRIPT = Path(__file__).resolve().parents[1] / "xray_shell.mjs"


def _shell(context, mode: str, width: int = 1440) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    done = subprocess.run(
        [node, str(SCRIPT), context.url, mode, str(width)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout.strip().splitlines()[-1])
    assert seen["ready"], f"the page did not draw the fixture in mode {mode}"
    return seen


def _expected_counts(context) -> dict[str, int]:
    view = context.fixture
    return {
        "graph": len(view["nodes"]),
        "calls": sum(len(t["calls"]) for t in view["track"]),
        "sources": len(view["sources"]) + len(view.get("builtin") or []),
    }


def _tabs_say(context, selected: str, shown: str) -> None:
    seen = _shell(context, "tabs")
    if seen is None:
        return
    assert [t["tab"] for t in seen["tabs"]] == ["graph", "calls", "sources"], seen["tabs"]
    assert {t["tab"]: t["count"] for t in seen["tabs"]} == _expected_counts(context), seen["tabs"]
    assert [t["tab"] for t in seen["tabs"] if t["selected"]] == [selected], seen["tabs"]
    assert seen["shown"] == [shown], seen["shown"]
    assert "Esc closes" in seen["hint"], seen["hint"]
    assert seen["toolbar"] is False, "the toolbar or an agent-type filter is still drawn"
    assert seen["afterClick"] == {"selected": "sources", "shown": ["sources"]}, seen["afterClick"]


@then("the page opens on the Tool calls tab with each tab's count from the view and no toolbar")
def step_opens_on_calls(context):
    _tabs_say(context, "calls", "calls")


@then("the page opens on the Graph tab with each tab's count from the view")
def step_opens_on_graph(context):
    _tabs_say(context, "graph", "graph")


@then("a double-click on a card leaves the page at its level and a click selects the card")
def step_double_click(context):
    seen = _shell(context, "cards")
    if seen is None:
        return
    assert seen["afterDouble"]["hash"] == seen["afterDouble"]["start"], seen["afterDouble"]
    assert seen["afterDouble"]["sel"] is None, seen["afterDouble"]
    assert seen["afterClick"]["sel"] == "a4", seen["afterClick"]
    assert seen["afterClick"]["hash"] == seen["afterDouble"]["start"], seen["afterClick"]


@then("hover and keyboard focus on a source highlight it, move no element and keep the hint bar's height")
def step_still(context):
    seen = _shell(context, "still")
    if seen is None:
        return
    assert seen["count"] > 50, seen  # the measure covered the page
    assert seen["hovered"], "hovering a source did not highlight anything"
    assert seen["focused"]["source"], seen["focused"]
    assert seen["hoverMoved"] == [], seen["hoverMoved"]
    assert seen["focusMoved"] == [], seen["focusMoved"]
    assert seen["hintBefore"] == seen["hintHover"] == seen["hintFocus"], seen


@then(
    "a click on a source opens a dialog inside the canvas column with focus on its close button, and Escape closes it, "
    "returns focus to the source, and a second Escape clears the selection"
)
def step_overlay(context):
    seen = _shell(context, "overlay")
    if seen is None:
        return
    r = seen["rects"]
    dlg, col = r["dialog"], r["col"]
    assert dlg["left"] >= col["left"] - 1 and dlg["right"] <= col["right"] + 1, r
    assert r["back"]["left"] >= col["left"] - 1 and r["back"]["right"] <= col["right"] + 1, r
    assert dlg["right"] <= r["inspector"]["left"] + 1 and dlg["left"] >= r["sources"]["right"] - 1, r
    assert seen["dialog"]["role"] == "dialog" and seen["dialog"]["modal"] == "false", seen["dialog"]
    assert seen["dialog"]["label"], seen["dialog"]
    assert seen["dialog"]["maxWidth"] == "860px", seen["dialog"]
    assert "blur(2px)" in seen["dialog"]["blur"] and seen["dialog"]["tint"] == "rgba(13, 14, 16, 0.74)", seen["dialog"]
    assert seen["focusOnOpen"]["closePeek"], seen["focusOnOpen"]
    assert seen["scrolled"]["scrollY"] > 0, seen["scrolled"]  # the page did scroll, and the dialog stayed in view
    assert 0 <= seen["scrolled"]["top"] < seen["scrolled"]["vh"], seen["scrolled"]
    assert seen["sel"] == "a4", seen
    assert seen["afterEsc1"]["dialog"] is False and seen["afterEsc1"]["sel"] == "a4", seen["afterEsc1"]
    assert seen["afterEsc1"]["focus"]["source"] == seen["opener"], (seen["afterEsc1"], seen["opener"])
    assert seen["afterEsc2"] == {"sel": None, "dialog": False}, seen["afterEsc2"]
    assert seen["afterBackdrop"]["dialog"] is False, seen["afterBackdrop"]
    assert seen["afterBackdrop"]["focus"]["source"] == seen["opener"], seen["afterBackdrop"]


@then("a click on a source on the Tool calls tab fills the side panel with no overlay, and Escape closes it")
def step_side_panel(context):
    seen = _shell(context, "side")
    if seen is None:
        return
    assert seen["panel"]["title"], seen["panel"]
    assert seen["panel"]["overlay"] is False and seen["panel"]["dialogs"] == 0, seen["panel"]
    assert seen["panel"]["title"] == seen["panel"]["sourceName"] or seen["panel"]["sourceName"].endswith(
        seen["panel"]["title"]
    ), seen["panel"]
    assert seen["focus"]["closePeek"], seen["focus"]
    assert seen["closed"]["panel"] is False and seen["closed"]["focus"]["source"], seen["closed"]


@then("at 1280 pixels the page and the graph column do not scroll sideways and the graph is scaled down")
def step_fits(context):
    seen = _shell(context, "fit", 1280)
    if seen is None:
        return
    fit = seen["fit"]
    assert fit["scrollWidth"] <= fit["innerWidth"], fit
    assert fit["wrapScroll"] <= fit["wrapClient"] and fit["colScroll"] <= fit["colClient"], fit
    assert float(fit["zoom"]) < 1, fit
    assert round(fit["sources"]) == 244 and round(fit["right"]) == 312, fit


@then(
    "every visible text on the Graph tab, with details open, and on the Tool calls tab is at least 10.5 pixels "
    "with 4.5 to 1 contrast"
)
def step_type_and_contrast(context):
    seen = _shell(context, "type")
    if seen is None:
        return
    for where in ("graph", "withPeek", "calls"):
        assert seen[where]["sizes"] == [], (where, seen[where]["sizes"][:8])
        assert seen[where]["contrast"] == [], (where, seen[where]["contrast"][:8])
