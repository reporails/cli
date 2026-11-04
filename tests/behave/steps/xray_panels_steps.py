"""Step definitions for the Sources panel, the right column and the details contents of the x-ray page."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from behave import then  # type: ignore[import-untyped]

from reporails_cli.core.discovery.agent_discovery import claude_project_folder_name

SCRIPT = Path(__file__).resolve().parents[1] / "xray_panels.mjs"


def _panels(context, mode: str, *grown: str) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    done = subprocess.run(
        [node, str(SCRIPT), context.url, mode, *grown],
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


@then("the session cost details count the replies that could not be priced as replies")
def step_unpriced(context):
    seen = _panels(context, "unpriced")
    if seen is None:
        return
    n = context.fixture["session_cost"]["unpriced"]
    assert n > 0 and f"{n} replies not priced" in seen["cost"], seen["cost"]


@then("hovering a Sources row of a kind whose eye is off still highlights that row")
def step_eye_hover(context):
    seen = _panels(context, "eye_hover")
    if seen is None:
        return
    assert seen["eyePressed"] == "false", seen
    assert seen["hovered"] is True, seen


@then("hovering spine items and groups changes nothing, and clicking a spine item opens its details")
def step_hover_calm(context):
    _hover_calm(_panels(context, "hover_calm"))


def _hover_calm(seen: dict | None) -> None:
    if seen is None:
        return
    assert seen["hovered"] > 0, seen
    assert seen["columnAfter"] == seen["columnBefore"], (seen["columnBefore"], seen["columnAfter"])
    assert seen["openAfter"] == seen["openBefore"], (seen["openBefore"], seen["openAfter"])
    assert seen["station"] and seen["dialog"] and seen["title"], seen


@then("a source pinned on the graph stays pinned after the view changes and until it is cleared")
def step_pin(context):
    _pinned(_panels(context, "pin"))


def _pinned(seen: dict | None) -> None:
    if seen is None:
        return
    assert seen["pinnedByClick"] is False, seen
    assert seen["pinned"] and seen["clearAtOnce"] is True, seen
    assert seen["whileHovering"] == seen["pinned"], seen
    assert seen["afterUpdate"] == seen["pinned"] and seen["clearAfterUpdate"] is True, seen
    assert seen["clearAfterClear"] is False, seen


@then("every group's eye toggle lies within its title line, also with a second line under it")
def step_eye_line(context):
    seen = _panels(context, "eye_line")
    if seen is None:
        return
    rows = [*seen["rows"], seen["hiddenRow"]]
    assert seen["hiddenRow"]["subTop"] is not None, seen
    for r in rows:
        assert r["titleTop"] - 0.5 <= r["eyeTop"] and r["eyeBottom"] <= r["titleBottom"] + 0.5, r
        assert r["subTop"] is None or r["eyeBottom"] <= r["subTop"] + 0.5, r


def _dollars(text: str) -> list[float]:
    return [float(m) for m in re.findall(r"\$([\d.]+)", text.replace(",", ""))]


@then("a subagent's cost tile shows dollars and the main tile's session figure is the sum of the agents")
def step_sub_cost(context):
    session = _agent_costs(_panels(context, "sub_cost"))
    if session is not None:
        cost = context.fixture["session_cost"]
        assert abs(session - cost["total_usd"]) <= 0.011, (session, cost)


def _agent_costs(seen: dict | None) -> float | None:
    """Checks a subagent's tile shows dollars and the main tile's session line is its own cost plus the subagents';
    returns the session figure."""
    if seen is None:
        return None
    sub = _dollars(" ".join(seen["subTile"]))
    assert sub, seen["subTile"]
    main = _dollars(" ".join(seen["mainTile"]))
    assert len(main) >= 3, seen["mainTile"]
    own, session, subs = main[0], main[1], main[2]
    assert abs(session - (own + subs)) <= 0.011, seen["mainTile"]
    return session


def _grown(context) -> tuple[str, str]:
    """The session file of the real run and the reply row appended to it when the page should take a new view."""
    from steps.xray_steps import SESSION_ID, _reply, _usage  # behave puts features/ on sys.path

    folder = context.home / ".claude" / "projects" / claude_project_folder_name(context.project)
    reply = _reply(
        30, "2.1.309", context.project, "msg_late", [{"type": "text", "text": "one more"}], _usage(2000, 400), "r"
    )
    reply.pop("requestRef")
    assert reply["sessionId"] == SESSION_ID
    return str(folder / "session.jsonl"), json.dumps(reply)


@then("on the real page hovering changes nothing in the right column and a click on a spine source opens its details")
def step_real_hover(context):
    _hover_calm(_panels(context, "hover_calm"))


@then("on the real page a pin survives the session file growing and the page taking the new view")
def step_real_pin(context):
    seen = _panels(context, "pin", *_grown(context))
    _pinned(seen)
    if seen is not None:
        assert seen["versionAfter"] != seen["versionBefore"], f"the page never took a new view: {seen}"


@then("on the real page the subagent's cost tile shows dollars and the main tile's session line is main plus subagents")
def step_real_cost(context):
    assert _agent_costs(_panels(context, "sub_cost")) is not None or context.scenario.status == "skipped"
