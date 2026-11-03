"""Step definitions for the Sources panel, the right column and the details contents of the x-ray page."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from behave import then  # type: ignore[import-untyped]

SCRIPT = Path(__file__).resolve().parents[1] / "xray_panels.mjs"


def _panels(context, mode: str) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    done = subprocess.run(
        [node, str(SCRIPT), context.url, mode],
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


def _tokens(text: str) -> float:
    number = re.search(r"([\d.]+)([kM]?)", text)
    assert number, text
    return float(number.group(1)) * {"": 1, "k": 1e3, "M": 1e6}[number.group(2)]


def _kept(groups: list[dict]) -> list[tuple]:
    return [(g["kind"], g["used"], g["total"], g["rows"], g["more"]) for g in groups]


@then("turning an eye off changes only the graph, never the Sources groups or their item counts")
def step_eye(context):
    seen = _panels(context, "eye")
    if seen is None:
        return
    assert _kept(seen["before"]) == _kept(seen["after"]), (seen["before"], seen["after"])
    agents = next(g for g in seen["after"] if g["kind"] == "agent")
    assert agents["off"] == "subagents hidden on the graph", agents
    assert agents["eye"] == "Show subagents on the graph", agents
    assert seen["after"][0]["kind"] == "builtin"


@then("headers carry one used of total figure and a findings line only with findings, and rows say their facts")
def step_headers(context):
    seen = _panels(context, "rows")
    if seen is None:
        return
    view = context.fixture
    by_kind = {g["kind"]: g for g in seen["groups"]}
    assert next(iter(by_kind)) == "builtin" and by_kind["builtin"]["eye"] is None
    assert list(by_kind)[1:] == [k["key"] for k in view["adapter"]["source_kinds"]], list(by_kind)
    for key, group in by_kind.items():
        assert group["dots"] == 0, f"{key} header carries a status dot"
    rules = by_kind["rule"]
    assert (rules["used"], rules["total"], rules["title"]) == ("1", "/2", "1 of 2 loaded"), rules
    assert by_kind["instructions"]["finds"] == "21 findings", by_kind["instructions"]
    assert by_kind["skill"]["finds"] is None and by_kind["skill"]["off"] is None, by_kind["skill"]
    rows = {r["id"]: r for r in seen["rows"]}
    assert re.fullmatch(r"~2\.5k tok · ~\$0\.01 · 21 findings", rows["CLAUDE.md"]["line2"]), rows["CLAUDE.md"]
    assert rows["packages/cli/CLAUDE.md"]["line2"] == "not loaded", rows["packages/cli/CLAUDE.md"]
    assert rows[".claude/rules/rules-engine.md"]["scoped"], rows[".claude/rules/rules-engine.md"]
    assert rows["builtin-agent:Explore"]["line2"] == "built in · launched as 1 subagent", rows["builtin-agent:Explore"]
    assert rows["builtin:system_prompt"]["line2"].startswith("~2.8k tok"), rows["builtin:system_prompt"]


@then("the right column shows the main agent, then a selected subagent, and the context rows add up")
def step_column(context):
    seen = _panels(context, "column")
    if seen is None:
        return
    view = context.fixture
    nodes = {n["id"]: n for n in view["nodes"]}
    assert seen["main"]["kicker"] == "Viewing · main agent" and seen["main"]["back"] is None, seen["main"]
    assert seen["main"]["output"] is None and not seen["main"]["drill"], seen["main"]
    assert seen["main"]["chips"] == len(view["adapter"]["source_kinds"]), seen["main"]
    sub = seen["sub"]
    assert sub["kicker"] == "Selected · depth 1" and sub["back"] == "← main agent", sub
    assert sub["output"] and sub["output"].startswith("Output") and "Returned to main agent" in sub["output"], sub
    assert "came back" not in sub["output"] and sub["drill"], sub
    assert any(text.startswith("Parent had but didn't pass on:") for text in sub["withheld"]), sub["withheld"]
    assert seen["again"]["kicker"] == "Viewing · main agent" and seen["again"]["back"] is None, seen["again"]
    for shown, node_id in ((seen["main"], "main"), (sub, "a4")):
        node = nodes[node_id]
        ic = node["detail"]["in_context"]
        assert len(shown["rows"]) == len(ic["rows"]), shown["rows"]
        assert not ic["over"]
        total = sum(_tokens(r["size"]) for r in shown["rows"])
        assert abs(total - ic["total"]) <= 0.02 * ic["total"], (total, ic["total"])
        assert shown["tools"] == [{"tool": t["tool"], "n": t["calls"]} for t in node["tools"]], shown["tools"]


@then("a source opens its text from the file route and the peak legend adds up to the whole")
def step_details(context):
    seen = _panels(context, "details")
    if seen is None:
        return
    assert seen["source"]["title"] == "CLAUDE.md" and seen["source"]["text"] == "text of CLAUDE.md", seen["source"]
    assert "Loaded by" in seen["source"]["body"] and "21 findings" in seen["source"]["body"], seen["source"]["body"]
    assert "Est. cost" in seen["source"]["body"] and "Method" in seen["source"]["body"]
    total = sum(int(p.rstrip("%")) for p in seen["peak"]["pcts"])
    assert 97 <= total <= 103, seen["peak"]
    comp = next(n for n in context.fixture["nodes"] if n["id"] == "main")["detail"]["composition"]
    assert seen["peak"]["title"] == f"{comp['replies'][comp['peak']][1]:,} tokens", seen["peak"]
    assert "Most expensive turn" in seen["cost"] and "list price" in seen["cost"], seen["cost"]
