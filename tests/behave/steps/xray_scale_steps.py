"""Step definitions for the x-ray design-scale scenarios."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from behave import given, then  # type: ignore[import-untyped]

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import xray_scale_view

SCRIPT = Path(__file__).resolve().parents[1] / "xray_scale.mjs"
MIN_FPS = 30


@given("the bundled page is served over a synthetic view at the design scale")
def step_serve_scale(context):
    path = Path(tempfile.gettempdir()) / f"xray_scale_{os.getpid()}.json"
    context.scale_view = xray_scale_view.write(path)
    context.add_cleanup(lambda: path.unlink(missing_ok=True))
    context.execute_steps(f'Given the bundled page is served over the "{str(path)[:-5]}" fixture view')


def _measure(context, mode: str, width: int = 1440) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    done = subprocess.run(
        [node, str(SCRIPT), context.url, mode, str(width)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    assert done.returncode == 0, done.stderr
    seen = json.loads(done.stdout.strip().splitlines()[-1])
    print(f"measured {mode}: {json.dumps(seen)}")
    return seen


@then("the Graph tab draws within {ms:d} ms, keeps every layer under {cap:d} elements and scrolls at 30 fps or better")
def step_graph(context, ms, cap):
    seen = _measure(context, "graph")
    if seen is None:
        return
    assert seen["firstRenderMs"] <= ms, f"first render {seen['firstRenderMs']} ms"
    assert seen["biggestLayer"]["count"] < cap, f"a layer holds {seen['biggestLayer']}"
    for key in ("scroll", "openScroll", "deepScroll"):
        assert seen[key]["fps"] >= MIN_FPS, f"graph {key} {seen[key]}"
    assert seen["groupsOpened"] >= 3 and seen["openCanvasEls"] < cap * 8, seen


@then(
    "the Tool calls table lists all {n:d} calls with fewer than 200 rows in the page "
    "and the tables scroll at 30 fps or better"
)
def step_tables(context, n):
    assert sum(len(t["calls"]) for t in context.scale_view["track"]) == n
    seen = _measure(context, "calls")
    if seen is None:
        return
    assert seen["summary"].startswith(f"{n} of {n} calls"), seen["summary"]
    assert 0 < seen["rows"] < 200 and 0 < seen["rowsAfter"] < 200, seen
    assert seen["listHeight"] >= n * 20, seen["listHeight"]
    assert 0 < seen["sourceRows"] < 200 and seen["sourceTotal"] >= len(context.scale_view["sources"]), seen
    assert seen["scroll"]["fps"] >= MIN_FPS, f"calls scroll {seen['scroll']}"
    assert seen["sourceScroll"]["fps"] >= MIN_FPS, f"sources scroll {seen['sourceScroll']}"


@then("at 1280 px there is no horizontal scroll and no two cards overlap")
def step_narrow(context):
    seen = _measure(context, "narrow", 1280)
    if seen is None:
        return
    assert seen["openCards"] >= 36, seen
    assert seen["clipped"] == 0, seen
    assert seen["overflow"]["page"] <= 0 and seen["overflow"]["graph"] <= 0, seen["overflow"]
    assert not seen["overlaps"], seen["overlaps"]
    assert seen["stationOverlaps"] == 0, seen["stationOverlaps"]
