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


def _closed_full_width(seen: dict, bar: bool) -> None:
    assert seen["sideHidden"] is True and seen["side"] == 0, seen
    assert seen["tiles"] == 0, "the agent summary is still drawn on the tab"
    assert abs(seen["table"] - seen["main"]) <= 1, seen
    if bar:
        assert seen["barHeight"] < 64 and max(seen["tops"]) - min(seen["tops"]) < 20, seen


def _open_beside(seen: dict, keep: list[str]) -> None:
    assert seen["sideHidden"] is False and seen["panel"] is True, seen
    assert seen["table"] < seen["main"] * 0.4 and seen["side"] > seen["table"], seen
    assert seen["sideLeft"] >= seen["tableRight"] - 1, seen
    assert seen["cols"] == 2, ("the details are not in the overlay's two-column layout", seen)
    assert seen["cut"] is False and seen["pageScroll"] is False, seen
    assert seen["head"][: len(keep)] == keep or [h for h in seen["head"] if h] == keep, (seen["head"], keep)
    assert seen["hasOn"] and seen["inView"], ("the clicked row is not marked and in view", seen)


@then("the Tool calls tab has no right pane and its bar does not wrap at 1280 pixels")
def step_calls_full(context):
    seen = _shell(context, "layout_calls", 1280)
    if seen is None:
        return
    _closed_full_width(seen["closed"], bar=True)


@then(
    "a click on a call narrows the table to its identifying columns and opens the details beside it, and "
    "Escape restores the full width"
)
def step_calls_beside(context):
    seen = _shell(context, "layout_calls", 1280)
    if seen is None:
        return
    _open_beside(seen["open"], ["Time", "Tool", "Call"])
    _closed_full_width(seen["after"], bar=True)
    assert "vl-row" in seen["after"]["focus"], seen["after"]


@then(
    "the Sources tab has no right pane, a click on a source narrows it and opens the details beside it, and "
    "Escape restores the full width"
)
def step_sources_beside(context):
    seen = _shell(context, "layout_sources", 1280)
    if seen is None:
        return
    _closed_full_width(seen["closed"], bar=False)
    _open_beside(seen["open"], ["", "Name", "Kind"])
    _closed_full_width(seen["after"], bar=False)


@then(
    "the strip spans the table at the canvas's pixel width with full-height marks, and "
    "a click on a mark opens its call while a click on a gap opens nothing"
)
def step_strip(context):
    seen = _shell(context, "strip", 1280)
    if seen is None:
        return
    box = seen["box"]
    assert abs(box["w"] - box["table"]) <= 2, ("the strip is narrower than the table", box)
    assert box["px"] == round(box["w"] * box["dpr"]), box
    assert seen["run"]["width"] >= 2 and seen["run"]["fullHeight"] is True, seen["run"]
    assert seen["hover"] and seen["hover"]["title"], ("no mark names itself on hover", seen["hover"])
    assert seen["gap"] is not None and seen["gapOpened"] is False, ("a click on a gap opened a call", seen)
    assert seen["opened"]["on"] == seen["opened"]["peek"], seen["opened"]
    assert seen["opened"]["title"], seen["opened"]
    for ticks in (seen["ticks"], seen["openTicks"]):
        # the first and last tick sit at the first and last mark's centre, narrow or wide
        assert abs(ticks["first"] - 1) <= 1 and abs(ticks["last"] - 1) <= 1, ("ticks are off the marks' x", seen)


@then(
    "after the viewport narrows the strip is redrawn at the new width, a "
    "click opens the right call and Escape focuses its row"
)
def step_strip_resize(context):
    seen = _shell(context, "strip_resize", 1280)
    if seen is None:
        return
    before, after = seen["before"], seen["after"]
    assert after["px"] != before["px"] and after["px"] == round(after["w"] * after["dpr"]), (before, after)
    assert seen["hover"], "no mark names itself after the resize"
    assert seen["opened"]["on"] == seen["opened"]["peek"], ("the click after the resize opened another call", seen)
    assert seen["focus"]["row"] and seen["focus"]["peek"] == seen["opened"]["peek"], (
        "focus did not return to the row",
        seen,
    )


@then(
    "on a screen of 1000 pixels the open details sit under the table in "
    "one column, and at 700 pixels nothing scrolls sideways"
)
def step_screens(context):
    seen = _shell(context, "screens", 1000)
    if seen is None:
        return
    for key in ("calls1000", "calls700", "sources700"):
        assert seen[key]["cols"] == 1 and seen[key]["sideVisible"] and seen[key]["below"], (key, seen[key])
        # the header's adapter chip is 1 px wide of a 1000 px screen on its own; nothing of the table or details is
        assert not [w for w in seen[key]["wide"] if any(c in w for c in ("tb-", "seg", "pk-", "vl", "sidepanel"))], (
            key,
            seen[key],
        )
        if key != "calls1000":
            assert seen[key]["pageScroll"] is False, (key, seen[key])


@then(
    "no element of the filter bar scrolls sideways, the plus menu filters by a tool "
    "without a button and open details collapse the bar to one button"
)
def step_bar(context):
    seen = _shell(context, "bar", 1280)
    if seen is None:
        return
    wide = seen["wide"]
    assert wide["scrolls"] == [] and max(wide["tops"]) - min(wide["tops"]) < 20, wide
    assert wide["menu"].startswith("+"), ("no +N button for the tools without a button", wide)
    assert seen["pick"] not in wide["buttons"] and seen["menuTools"], seen
    picked = seen["picked"]
    assert picked["menuOpen"] is False and picked["scrolls"] == [], picked
    assert picked["menu"].startswith(seen["pick"]) and picked["pressed"] == "true", (
        "the button does not name the active tool",
        picked,
    )
    assert picked["tools"] == [seen["pick"]], ("the table is not filtered by the hidden tool", picked)
    pane = seen["pane"]
    assert pane["scrolls"] == [] and pane["menu"] == "Filters" and pane["buttons"] == [], pane
    assert seen["paneGroups"][-2:] == ["Tools", "Status"], seen["paneGroups"]
    assert seen["paneFailed"]["menu"] == "failed", seen["paneFailed"]
