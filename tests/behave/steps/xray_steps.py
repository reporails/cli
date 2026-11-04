"""Step definitions for the x-ray demonstrations: the real `ails xray` binary and its page over HTTP."""

from __future__ import annotations

import base64
import itertools
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import parse_qs, urlparse

from behave import given, then, when  # type: ignore[import-untyped]
from support import AILS_BIN, build_project, run_ails  # behave puts features/ on sys.path

from reporails_cli.bundled import get_xray_path
from reporails_cli.core.discovery.agent_discovery import claude_project_folder_name
from reporails_cli.core.eventbus.adapters.claude_requests import message_hash
from tests.suite_env import suite_env

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript" / "2.1.308"
STARTUP_LIMIT_S = 60


def _start(context) -> None:
    assert AILS_BIN is not None, "`ails` console script not on PATH (run via `uv run behave`)"
    env = {**suite_env(os.environ), "HOME": str(context.home), "USERPROFILE": str(context.home)}
    proc = subprocess.Popen(  # pylint: disable=consider-using-with  # stopped by the scenario cleanup
        [str(AILS_BIN), "xray", "--no-open"],
        cwd=str(context.project),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    context.add_cleanup(proc.kill)
    watchdog = threading.Timer(STARTUP_LIMIT_S, proc.kill)
    watchdog.start()
    context.add_cleanup(watchdog.cancel)
    context.xray_line = proc.stdout.readline()


@given("a project with a recorded Claude Code session")
def step_project_with_session(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    folder = context.home / ".claude" / "projects" / claude_project_folder_name(context.project)
    folder.mkdir(parents=True)
    shutil.copytree(FIXTURE / "session", folder / "session")
    text = (FIXTURE / "session.jsonl").read_text(encoding="utf-8").replace("/work/proj", str(context.project))
    (folder / "session.jsonl").write_text(text, encoding="utf-8")


@given("a project with a recorded Claude Code session that compacted twice")
def step_project_with_compactions(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    folder = context.home / ".claude" / "projects" / claude_project_folder_name(context.project)
    folder.mkdir(parents=True)
    source = FIXTURE.parent / "2.1.309-compactions" / "session.jsonl"
    (folder / "session.jsonl").write_text(
        source.read_text(encoding="utf-8").replace("/work/proj", str(context.project)), encoding="utf-8"
    )


@given('the project\'s instruction file reads "{text}"')
def step_instruction_text(context, text):
    (context.project / "CLAUDE.md").write_text(text + "\n", encoding="utf-8")


@given('the project\'s memory folder holds an unlinked topic file reading "{text}"')
def step_unlinked_memory(context, text):
    memory = context.home / ".claude" / "projects" / claude_project_folder_name(context.project) / "memory"
    memory.mkdir()
    (memory / "MEMORY.md").write_text("# Memory\n", encoding="utf-8")
    (memory / "feedback_orphan.md").write_text(f"---\ntype: feedback\n---\n{text}\n", encoding="utf-8")


@given('the project\'s memory folder holds an unlinked note named "{name}" reading "{text}"')
def step_unlinked_named_memory(context, name, text):
    memory = context.home / ".claude" / "projects" / claude_project_folder_name(context.project) / "memory"
    memory.mkdir()
    (memory / "MEMORY.md").write_text("# Memory\n", encoding="utf-8")
    (memory / name).write_text(f"---\ntype: feedback\n---\n{text}\n", encoding="utf-8")


@given('the session\'s first prompt was typed and reads "{text}"')
def step_typed_prompt(context, text):
    session = next((context.home / ".claude" / "projects").rglob("session.jsonl"))
    rows = [json.loads(row) for row in session.read_text(encoding="utf-8").splitlines()]
    first = rows[0]
    first["uuid"] = "typed-prompt-1"
    first["promptSource"] = "typed"
    first["origin"] = {"kind": "human"}
    first["message"]["content"] = text
    session.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


SESSION_ID = "11111111-2222-3333-4444-555555555555"
SUB_ID = "aaaa0000000000001"


def _row(kind: str, second: int, version: str, project: Path, **fields: object) -> dict:
    return {
        "type": kind,
        "timestamp": f"2026-10-31T10:00:{second:02d}.000Z",
        "sessionId": SESSION_ID,
        "version": version,
        "cwd": str(project),
        **fields,
    }


def _usage(read: int, created: int) -> dict:
    return {
        "input_tokens": 2,
        "cache_creation_input_tokens": created,
        "cache_read_input_tokens": read,
        "output_tokens": 5,
    }


def _reply(second: int, version: str, project: Path, mid: str, content: list, usage: dict, ref: str) -> dict:
    message = {"id": mid, "role": "assistant", "model": "claude-sonnet-5-5", "content": content, "usage": usage}
    return _row("assistant", second, version, project, message=message, requestRef=ref)


FIXTURE_TOOLS = [{"name": f"Tool{n}", "description": "d" * 400} for n in range(6)]


def _shape_row(shape: str, system: str) -> dict:
    return {
        "type": "api-request-shape",
        "shapeHash": shape,
        "shape": {"system": [{"type": "text", "text": system}], "tools": FIXTURE_TOOLS},
    }


def _chars(value: object) -> int:
    """The characters of `value` written as compact JSON."""
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False))


def _expected_shares(peak: int, *, system: int, other: int, calls: int, images: int = 0) -> dict[str, int]:
    """The rows a measured peak must show: the request's characters scaled to the reply's exact `peak` total, the
    system blocks, the tool definitions and the tool calls and results each taking their own share. `other` is the
    characters of the messages that are neither tool calls nor tool results. The `images` tokens of a picture in a
    tool result come off the total before the text is scaled, and sit in the tool row."""
    tools = sum(_chars(tool) for tool in FIXTURE_TOOLS)
    scale = (peak - images) / (system + tools + calls + other)
    return {
        "system_prompt": round(system * scale),
        "tool_definitions": round(tools * scale),
        "tool_io": round(calls * scale) + images,
    }


def _request_row(rid: str, shape: str, keep: int, tail: list[str], second: int, project: Path) -> dict:
    """An `api-request` row: the messages it keeps from the previous request, the hashes of those it appends and
    the model it was sent to."""
    params = {"model": "claude-opus-5-5"}
    return _row("api-request", second, "2.1.309", project, id=rid, shapeHash=shape, keep=keep, tail=tail, params=params)


# A 1920x1080 picture costs 1560 visual tokens on a standard model and 2691 on a high-resolution one; only the PNG
# header has to be real.
_PNG_HEADER = (
    b"\x89PNG\r\n\x1a\n" + (13).to_bytes(4, "big") + b"IHDR" + (1920).to_bytes(4, "big") + (1080).to_bytes(4, "big")
)
PICTURE = {
    "type": "image",
    "source": {"type": "base64", "media_type": "image/png", "data": base64.b64encode(_PNG_HEADER + bytes(9)).decode()},
}
PICTURE_TOKENS = 2691


def _peak(rows: list[dict]) -> int:
    totals = [
        row["message"]["usage"]["input_tokens"]
        + row["message"]["usage"]["cache_read_input_tokens"]
        + row["message"]["usage"]["cache_creation_input_tokens"]
        for row in rows
        if row["type"] == "assistant"
    ]
    return max(totals)


def _write_session(context, recorded: bool, *, picture: bool = False, configured: bool = False) -> None:
    """A fixture session of a main agent and one subagent. `recorded` adds the request rows Claude Code 2.1.309
    writes and the `requestRef` of each reply; an older Claude Code writes neither. Keeps the highest total of each
    agent's own replies, from its own file, in `context.peaks`. `configured` gives the subagent a launch config: a
    model asked for, a background run and the thinking, effort and max tokens its requests carry."""
    version = "2.1.309" if recorded else "2.1.308"
    project = context.project
    folder = context.home / ".claude" / "projects" / claude_project_folder_name(project)
    (folder / "session" / "subagents").mkdir(parents=True)
    ask, hello, listed = (
        "please summarise the layout",
        [{"type": "text", "text": "the layout is flat"}],
        "list the files",
    )
    launch = [
        {
            "type": "tool_use",
            "id": "toolu_sub1",
            "name": "Agent",
            "input": {
                "description": "look around",
                "subagent_type": "general-purpose",
                "prompt": listed,
                "run_in_background": True,
            },
        }
    ]
    done_content = [{"type": "text", "text": "launched"}, PICTURE] if picture else "launched"
    done = [{"type": "tool_result", "tool_use_id": "toolu_sub1", "content": done_content}]
    note = {"role": "user", "content": "and the tests"}
    main = [
        _row(
            "user",
            1,
            version,
            project,
            uuid="p-one",
            promptSource="typed",
            origin={"kind": "human"},
            message={"role": "user", "content": ask},
        ),
        _reply(2, version, project, "msg_1", hello, _usage(1000, 300), "req-main-1"),
        _row("user", 3, version, project, message=note),
        _reply(4, version, project, "msg_2", launch, _usage(1000, 800), "req-main-2"),
        _row("user", 5, version, project, message={"role": "user", "content": done}),
        _reply(
            6,
            version,
            project,
            "msg_3",
            [{"type": "text", "text": "all done"}],
            _usage(4000 if picture else 2000, 800 if picture else 400),
            "req-main-3",
        ),
    ]
    sub = [
        _row("user", 10, version, project, message={"role": "user", "content": listed}),
        _reply(11, version, project, "msg_s1", [{"type": "text", "text": "a b c"}], _usage(500, 200), "req-sub-1"),
        _reply(12, version, project, "msg_s2", [{"type": "text", "text": "d e f"}], _usage(900, 100), "req-sub-2"),
    ]
    for row in sub:
        row.update({"isSidechain": True, "agentId": SUB_ID})
    if not recorded:
        for row in (*main, *sub):
            row.pop("requestRef", None)
    if recorded:
        # each request row follows the rows its tail names; the note is known only as a blob
        u1, u2, u3, a1, a2, a3 = main[0], main[2], main[4], main[1], main[3], main[5]
        blob = {"type": "api-request-blob", "hash": "blob-note", "message": note}
        hashes = {
            "ask": message_hash("user", ask),
            "a1": message_hash("assistant", hello),
            "a2": message_hash("assistant", launch),
        }
        main = [
            _shape_row("shape-main", "s" * 2000),
            u1,
            _request_row("req-main-1", "shape-main", 0, [hashes["ask"]], 1, project),
            a1,
            blob,
            u2,
            _request_row("req-main-2", "shape-main", 1, [hashes["a1"], "blob-note"], 3, project),
            a2,
            u3,
            _request_row("req-main-3", "shape-main", 3, [hashes["a2"], message_hash("user", done)], 5, project),
            a3,
        ]
        sub_hash = message_hash("assistant", [{"type": "text", "text": "a b c"}])
        sub = [
            sub[0],
            _shape_row("shape-sub", "t" * 500),
            _request_row("req-sub-1", "shape-sub", 0, [message_hash("user", listed)], 10, project),
            sub[1],
            _request_row("req-sub-2", "shape-sub", 1, [sub_hash], 11, project),
            sub[2],
        ]
        if configured:
            config = {"model": "claude-sonnet-5-5", "max_tokens": 128000, "thinking": {"type": "adaptive"}}
            config["output_config"] = {"effort": "medium"}
            sub = [{**row, "params": config} if row["type"] == "api-request" else row for row in sub]
        sub = [{**row, "isSidechain": True, "agentId": SUB_ID} for row in sub]
    context.peaks = {"main": _peak(main), "sub": _peak(sub)}
    # the characters of the peak request of each agent, from the fixture's own texts
    main_calls = len("Agent") + _chars(launch[0]["input"]) + len("launched")
    main_other = len(ask) + len(note["content"]) + len(hello[0]["text"])
    sub_other = len(listed) + len("a b c")
    context.expected = {
        "main": _expected_shares(
            context.peaks["main"],
            system=2000,
            other=main_other,
            calls=main_calls,
            images=PICTURE_TOKENS if picture else 0,
        ),
        "sub": _expected_shares(context.peaks["sub"], system=500, other=sub_other, calls=0),
    }
    write = lambda path, rows: path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")  # noqa: E731
    write(folder / "session.jsonl", main)
    write(folder / "session" / "subagents" / f"agent-{SUB_ID}.jsonl", sub)
    meta = {
        "agentType": "general-purpose",
        "description": "look around",
        "toolUseId": "toolu_sub1",
        "spawnDepth": 1,
        "finished": True,
    }
    if configured:
        meta |= {"model": "sonnet", "requestShape": "background"}
    (folder / "session" / "subagents" / f"agent-{SUB_ID}.meta.json").write_text(json.dumps(meta), encoding="utf-8")


@given("a project with a session whose Claude Code recorded each request it made, with a subagent")
def step_session_with_requests(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    _write_session(context, True)


@given("a project with a session that loaded two of the project's instruction files, with a subagent")
def step_session_with_loaded_file(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    _write_session(context, True)
    session = context.home / ".claude" / "projects" / claude_project_folder_name(context.project) / "session.jsonl"
    attachment = {
        "type": "instructions",
        "files": [{"path": str(context.project / name), "type": "Project"} for name in ("CLAUDE.md", "AGENTS.md")],
    }
    loaded = _row("attachment", 0, "2.1.309", context.project, attachment=attachment)
    lines = session.read_text(encoding="utf-8").splitlines()
    lines.insert(1, json.dumps(loaded))
    session.write_text("\n".join(lines) + "\n", encoding="utf-8")


@given("a project with a session whose main requests were sent with two different system prompts")
def step_session_with_two_system_prompts(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    _write_session(context, True)
    session = context.home / ".claude" / "projects" / claude_project_folder_name(context.project) / "session.jsonl"
    rows = [json.loads(line) for line in session.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        if row.get("id") == "req-main-3":
            row["shapeHash"] = "shape-main-2"
    rows.insert(0, _shape_row("shape-main-2", "w" * 300))
    session.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


@given("a project with a session whose subagent was launched with a model and a config")
def step_session_with_launch_config(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    _write_session(context, True, configured=True)


@given("a project with a session whose peak request carries a picture inside a tool result, with a subagent")
def step_session_with_picture(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    _write_session(context, True, picture=True)


@given("a project with a session from an older Claude Code that did not record its requests, with a subagent")
def step_session_without_requests(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    _write_session(context, False)


def _k1(n: int) -> str:
    """A token count as the page writes it (`format.js` `k1`) for counts under ten thousand."""
    return str(n) if n < 1000 else f"{n / 1000:.1f}".rstrip("0").rstrip(".") + "k"


def _session_view(context) -> dict:
    status, page = _get(context.url)
    token = re.search(r'name="xray-token" content="([^"]+)"', page)
    assert status == 200 and token, "the page carries no launch token"
    status, body = _get(context.url + "view", token.group(1))
    assert status == 200, status
    return json.loads(body)


def _context_of(view: dict) -> tuple[dict, dict]:
    nodes = {node["id"]: node for node in view["nodes"]}
    (sub_id,) = [key for key in nodes if key != "main"]
    return nodes["main"]["detail"]["in_context"], nodes[sub_id]["detail"]["in_context"]


@then("the main agent's In context rows are measured, add up to its peak reply and name the system prompt and tools")
def step_main_measured(context):
    main, _ = _context_of(_session_view(context))
    keys = [row["key"] for row in main["rows"]]
    assert main["total"] == context.peaks["main"], (main["total"], context.peaks)
    assert sum(row["tokens_est"] for row in main["rows"]) == context.peaks["main"], main["rows"]
    assert main["measured"] is True, main
    assert {"system_prompt", "tool_definitions"} <= set(keys) and keys[-1] == "rest", keys


@then("the subagent's In context rows add up to the peak reply of its own file")
def step_sub_measured(context):
    _, sub = _context_of(_session_view(context))
    assert sub["measured"] is True and sub["total"] == context.peaks["sub"], (sub["total"], context.peaks)
    assert sum(row["tokens_est"] for row in sub["rows"]) == context.peaks["sub"], sub["rows"]
    assert {"system_prompt", "tool_definitions"} <= {row["key"] for row in sub["rows"]}


@then("each agent's system, tool definition and tool call rows are the shares of its request's own characters")
def step_measured_shares(context):
    main, sub = _context_of(_session_view(context))
    for name, ic in (("main", main), ("sub", sub)):
        rows = {row["key"]: row["tokens_est"] for row in ic["rows"]}
        got = {key: rows[key] for key in context.expected[name]}
        assert got == context.expected[name], (name, got, context.expected[name])


@then("the main agent's tool calls and results row holds the picture's tokens and its measure names them")
def step_picture_row(context):
    main, _ = _context_of(_session_view(context))
    row = next(row for row in main["rows"] if row["key"] == "tool_io")
    assert row["measure"]["images"] == PICTURE_TOKENS, row
    assert row["tokens_est"] >= PICTURE_TOKENS, row
    others = [r for r in main["rows"] if r["key"] in ("system_prompt", "tool_definitions")]
    assert all(r["measure"]["images"] == 0 for r in others), others


@then("each agent's measured System prompt row opens that agent's own figure and request")
def step_measured_row_opens_own(context):
    seen = _page(context, "measuredrow")
    if seen is None:
        return
    main, sub = _context_of(_session_view(context))
    for name, ic in (("main", main), ("sub", sub)):
        row = next(row for row in ic["rows"] if row["key"] == "system_prompt")
        text = seen[name]["text"]
        assert seen[name]["peek"].startswith("measured:system_prompt:"), seen[name]
        assert f"{_k1(row['tokens_est'])} · measured" in text, (name, row["tokens_est"], text)
        assert ic["request_id"] in text, (name, ic["request_id"], text)
        assert f"{row['measure']['chars']:,}" in text, (name, text)
    assert "What it contains" in seen["main"]["text"], seen["main"]
    assert "What it contains" not in seen["sub"]["text"], seen["sub"]
    assert main["request_id"] != sub["request_id"]
    assert main["request_id"] not in seen["sub"]["text"], seen["sub"]
    assert sub["request_id"] not in seen["main"]["text"], seen["main"]


@then("the page's In context list for each agent shows no remainder text and no asterisk")
def step_page_no_remainder(context):
    seen = _page(context, "inctx")
    if seen is None:
        return
    for name in ("main", "sub"):
        assert seen[name]["rows"] >= 3, seen
        assert "remainder" not in seen[name]["text"].lower() and "*" not in seen[name]["text"], seen[name]


@then("the main agent's In context list is not measured, keeps its remainder row and says it is an estimate")
def step_estimated_view(context):
    main, _ = _context_of(_session_view(context))
    assert main["measured"] is False, main
    assert main["note"] == "Estimated: no complete recorded request for this reply.", main["note"]
    assert "rest" in [row["key"] for row in main["rows"]] and "system_prompt" not in [
        row["key"] for row in main["rows"]
    ]


@then("the page shows the estimate note and a remainder row in the main agent's In context list")
def step_estimated_page(context):
    seen = _page(context, "inctx")
    if seen is None:
        return
    text = seen["main"]["text"]
    assert "Estimated: no complete recorded request for this reply." in text, text
    assert "remainder" in text.lower(), text


@then("the general-purpose agent type's details show its recorded system prompt and its tools with launch counts")
def step_agent_shape_on_page(context):
    seen = _layout_script(context, "agent")
    if seen is None:
        return
    assert seen["ready"] and seen["row"], seen
    assert seen["text"] == "t" * 500, seen
    assert seen["tools"].splitlines() == [f"Tool{n} · 1 launch" for n in range(6)], seen
    assert "Comes from the coding agent" not in seen["dialog"], seen
    assert "launchs" not in seen["dialog"], seen


@then("the system prompt route returns that text only for a type the session launched")
def step_system_route(context):
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    status, body = _get(context.url + "system?type=general-purpose", token)
    assert status == 200 and json.loads(body)["text"] == "t" * 500, (status, body)
    status, _ = _get(context.url + "system?type=Explore", token)
    assert status == 400, status


def _main_system(context) -> str:
    """The text of the main agent's system prompt route."""
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    status, body = _get(context.url + "system?type=", token)
    assert status == 200, (status, body)
    return json.loads(body)["text"]


@then("the main agent's System prompt details show the system prompt text of its recorded request")
def step_main_system_text(context):
    assert _main_system(context) == "s" * 2000
    seen = _page(context, "mainsystem")
    if seen is None:
        return
    assert seen["text"] == "s" * 2000, seen["text"][:80]
    assert "different system prompts" not in seen["dialog"], seen["dialog"][:300]


@then("the main agent's System prompt details say there were two and show the latest")
def step_main_system_latest(context):
    assert _main_system(context) == "w" * 300
    builtin = next(item for item in _session_view(context)["builtin"] if item["key"] == "system_prompt")
    assert builtin["system_shapes"] == 2, builtin
    seen = _page(context, "mainsystem")
    if seen is None:
        return
    assert seen["text"] == "w" * 300, seen["text"][:80]
    assert "2 different system prompts; this is the latest" in seen["dialog"], seen["dialog"][:300]


@then("the main agent's System prompt route refuses when the session recorded no request")
def step_main_system_none(context):
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    assert _get(context.url + "system?type=", token)[0] == 400
    builtin = next(item for item in _session_view(context)["builtin"] if item["key"] == "system_prompt")
    assert builtin["system_shapes"] == 0, builtin


@then("the general-purpose agent type's details show its launch settings")
def step_agent_launch_settings(context):
    seen = _layout_script(context, "agent")
    if seen is None:
        return
    assert seen["ready"] and seen["row"], seen
    settings = next((text for text in seen["pres"] if text.startswith("Model asked for")), "")
    assert settings.splitlines() == [
        "Model asked for · sonnet",
        "Model in requests · claude-sonnet-5-5",
        "Launched with defaults · not recorded",
        "Background · yes",
        "Thinking · adaptive",
        "Effort · medium",
        "Max tokens · 128000",
    ], seen


@given("a project with no recorded Claude Code session")
def step_project_without_session(context):
    context.project = build_project(context.tmpdir / "proj").resolve()


@when('"ails xray --no-open" is started in the project')
def step_start(context):
    _start(context)


@when('"ails xray --no-open" is run in the project')
def step_run(context):
    context.result = run_ails(context.project, "xray", "--no-open", home=context.home, timeout=60)


@then("the printed address is on 127.0.0.1")
def step_address(context):
    found = re.search(r"http://127\.0\.0\.1:\d+/", context.xray_line)
    assert found, f"no loopback address printed: {context.xray_line!r}"
    context.url = found.group(0)


def _get(url: str, token: str | None = None) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"X-Xray-Token": token} if token else {})
    try:
        with urllib.request.urlopen(request, timeout=30) as reply:
            return reply.status, reply.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, ""


@then("the page carries a launch token and the session view with that token holds the main agent")
def step_view(context):
    status, page = _get(context.url)
    assert status == 200
    token = re.search(r'name="xray-token" content="([^"]+)"', page)
    assert token and token.group(1) != "__XRAY_TOKEN__", "the page carries no launch token"
    status, body = _get(context.url + "view", token.group(1))
    assert status == 200, status
    assert [node["id"] for node in json.loads(body)["nodes"]][:1] == ["main"]


def _layout_script(context, mode: str, *args: str) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    script = Path(__file__).resolve().parents[1] / "xray_layout.mjs"
    done = subprocess.run(
        [node, str(script), context.url, mode, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


@then('opening the not-loaded memory file shows "{text}"')
def step_memory_selected(context, text):
    seen = _layout_script(context, "memory")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    sources = json.loads(_get(context.url + "view", token)[1])["sources"]
    names = [s["label"] for s in sources if s["path"] and s["path"].endswith("feedback_orphan.md")]
    assert names and seen["row"] == names[0], (names, seen)
    assert text in seen["text"], seen


@then("checking the instruction file lists each finding with the message the check route returns")
def step_finding_messages(context):
    seen = _layout_script(context, "check")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    request = urllib.request.Request(
        context.url + "check",
        data=json.dumps({"path": "CLAUDE.md"}).encode(),
        headers={"x-xray-token": token, "Origin": context.url.rstrip("/"), "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as reply:
        lines = json.loads(reply.read())["lines"]
    assert lines and len(seen["rows"]) == len(lines), (seen["rows"], lines)
    for row, line in zip(seen["rows"], lines, strict=True):
        assert line["message"] in row, (row, line)


@then("the prompt line shows no text and asks for none until it is clicked, then shows what the prompt route returns")
def step_prompt_on_click(context):
    seen = _layout_script(context, "prompt")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    assert seen["before"] == "0 0", seen
    page = _get(context.url)[1]
    token = re.search(r'name="xray-token" content="([^"]+)"', page).group(1)
    status, body = _get(context.url + "prompt?id=" + seen["id"], token)
    assert status == 200, status
    assert seen["text"] == json.loads(body)["text"] == "typed prompt text", (seen, body)


@then("the markup in the file name, the file and the prompt shows literally and no element or handler was injected")
def step_markup_is_text(context):
    seen = _layout_script(context, "markup")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    assert seen["row"] == "<img src=x onerror=window.__pwned=1>", seen
    assert seen["text"].strip().endswith("<b>bold</b>"), seen
    assert seen["promptText"] == "<b>bold</b> <img src=x onerror=window.__pwned=1>", seen
    assert seen["dom"] == {"pwned": None, "imgs": 0, "inPeek": 0, "rowChildren": 0}, seen


@then("the page's scripts write to no HTML sink")
def step_no_html_sink(context):
    scripts = sorted(get_xray_path().rglob("*.js"))
    assert scripts, "the page has no scripts"
    sinks = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|createContextualFragment|DOMParser")
    found = [
        f"{path.name}: {hit.group(0)}" for path in scripts for hit in sinks.finditer(path.read_text(encoding="utf-8"))
    ]
    assert not found, found


@then('the page shows "{first}" for the file, then "{second}" once the file and the session change')
def step_pane_follows_file(context, first, second):
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return
    script = Path(__file__).resolve().parents[1] / "xray_pane.mjs"
    proc = subprocess.Popen(  # pylint: disable=consider-using-with  # stopped by the scenario cleanup
        [node, str(script), context.url, "CLAUDE.md"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    context.add_cleanup(proc.kill)
    shown = proc.stdout.readline()
    assert first in shown, shown
    (context.project / "CLAUDE.md").write_text(second + "\n", encoding="utf-8")
    session = next((context.home / ".claude" / "projects").rglob("session.jsonl"))
    rows = session.read_text(encoding="utf-8").splitlines()
    later = json.loads(rows[-1])
    later["message"]["id"] = "msg_later"
    later["timestamp"] = "2026-10-30T20:11:39.626Z"
    session.write_text("\n".join([*rows, json.dumps(later)]) + "\n", encoding="utf-8")
    proc.stdin.write("go\n")
    proc.stdin.flush()
    after = proc.stdout.readline()
    assert second in after, after


@then("the session view without the token is refused with 403")
def step_no_token(context):
    assert _get(context.url + "view")[0] == 403


@then("it exits 2 saying no Claude Code session was found")
def step_refused(context):
    assert context.result.returncode == 2, context.result.returncode
    assert "no Claude Code session found" in context.result.stderr


@then("the page draws a compaction marker for each of the two compactions with the sizes the view holds")
def step_compaction_markers(context):
    seen = _layout_script(context, "compactions")
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    token = re.search(r'name="xray-token" content="([^"]+)"', _get(context.url)[1]).group(1)
    stations = json.loads(_get(context.url + "view", token)[1])["stations"]
    held = next(station["compactions"] for station in stations if station["node"] == "main")
    assert len(held) == 2 and len(seen["markers"]) == 2, (held, seen)
    for marker, item in zip(seen["markers"], held, strict=True):
        assert marker.startswith("compacted"), marker
        if item["before"] is not None and item["after"] is not None:
            assert f"{_k1(item['before'])} → {_k1(item['after'])}" in marker, (marker, item)


def _k1(n: int) -> str:
    return f"{n / 1000:.0f}k" if n >= 10_000 else f"{n / 1000:.1f}".removesuffix(".0") + "k" if n >= 1000 else str(n)


# ---- the bundled page over a fixture view, served by a server this file owns ----

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "xray"
STUB_NODE = Path(__file__).resolve().parents[1] / "xray_stub_node.js"
TOKEN = "fixture-token"
TYPES = {".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2", ".html": "text/html"}
CALLS = {"toolu_fail0": "npm test -- --runInBand"}
STUB_SESSIONS = [
    {"session": "sess-aaa", "started_at": "2026-10-28T09:14:02Z", "length_s": 7200.0, "subagents": 5},
    {"session": "sess-bbb", "started_at": "2026-10-27T16:40:00Z", "length_s": 95.0, "subagents": 0},
    {"session": "sess-ccc", "started_at": "2026-10-26T08:05:30Z", "length_s": 3725.0, "subagents": 1},
]
STUB_PROMPTS = {s["session"]: f"first prompt of {s['session']}" for s in STUB_SESSIONS}
SESSION_ROUTES = ("/view", "/peek", "/brief", "/system", "/prompt", "/call", "/sessions", "/first-prompt")


class _FixtureHandler(BaseHTTPRequestHandler):
    """The routes the page calls: its own files from the bundle, a fixture `/view`, and canned text routes."""

    view_text = ""
    bump_version = False
    requests: ClassVar[list[str]] = []
    views_served = 0
    overrides: ClassVar[dict] = {}
    swaps = 0
    call_result = True
    landed = False
    call_refused = False

    def log_message(self, *_args) -> None:  # silence the per-request log
        return

    def _send(self, status: int, body: bytes, kind: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _serve_view(self, query: dict[str, list[str]]) -> None:
        type(self).views_served += 1
        body = self.view_text
        if self.overrides or "session" in query:
            shown = {**json.loads(body), **self.overrides}
            if "session" in query:
                shown["session"] = query["session"][0]
            body = json.dumps(shown)
        if self.landed:  # a landed result: the view now times every call
            shown = json.loads(body)
            for track in shown["track"]:
                for item in track["calls"]:
                    item["duration_s"] = 1.0 if item["duration_s"] is None else item["duration_s"]
            body = json.dumps(shown)
        if self.swaps:  # a test changed the session: it is a new version of it
            body = json.dumps({**json.loads(body), "version": 5000 + self.swaps})
        if self.bump_version:  # a session that keeps growing: every poll carries a new version
            body = json.dumps({**json.loads(body), "version": 1000 + self.views_served})
        self._send(200, body.encode(), "application/json")

    def _test_route(self, path: str, query: dict[str, list[str]]) -> None:
        """The test-only routes: the stub node renderer, and the session moving on (another view, a landed result)."""
        if path == "/test/stub_node.js":
            return self._send(200, STUB_NODE.read_bytes(), "text/javascript")
        cls = type(self)
        if "view" in query:
            cls.view_text = (FIXTURES / f"{query['view'][0]}.json").read_text(encoding="utf-8")
        if "result" in query:
            cls.call_result = query["result"][0] == "1"
            cls.landed = cls.call_result
        cls.swaps += 1
        self._json(200, {"swaps": cls.swaps})

    def _call_result(self, key: str) -> str | None:
        return f"result of {key}" if self.call_result else None

    def _serve_call(self, key: str, text: str) -> None:
        if self.call_refused:
            return self._json(500, {"error": "the call route is refusing"})
        self._json(
            200,
            {
                "id": key,
                "tool": "Bash",
                "text": text,
                "input": f'{{"command": "{text}"}}',
                "result": self._call_result(key),
                "truncated": False,
            },
        )

    def do_GET(self) -> None:  # http.server's name
        url = urlparse(self.path)
        query = parse_qs(url.query)
        root = get_xray_path()
        if url.path == "/":
            page = (root / "index.html").read_text(encoding="utf-8").replace("__XRAY_TOKEN__", TOKEN)
            return self._send(200, page.encode(), "text/html")
        if url.path.startswith("/static/"):
            target = (root / url.path.removeprefix("/static/")).resolve()
            if not target.is_file() or root.resolve() not in target.parents:
                return self._json(404, {"error": "no such file"})
            return self._send(200, target.read_bytes(), TYPES.get(target.suffix, "application/octet-stream"))
        if url.path in ("/test/swap", "/test/stub_node.js"):
            return self._test_route(url.path, query)
        if self.headers.get("X-Xray-Token") != TOKEN:
            return self._json(403, {"error": "token"})
        if url.path == "/test/requests":
            return self._json(200, type(self).requests)
        type(self).requests.append(self.path)
        if url.path == "/sessions":
            return self._json(
                200, {"session": query.get("session", [STUB_SESSIONS[0]["session"]])[0], "sessions": STUB_SESSIONS}
            )
        if url.path == "/first-prompt":
            wanted = query.get("session", [""])[0]
            return self._json(200, {"id": wanted, "text": STUB_PROMPTS.get(wanted, "")})
        if url.path == "/view":
            return self._serve_view(query)
        key = query.get("id", query.get("subagent", query.get("path", [""])))[0]
        texts = {
            "/call": CALLS.get(key, ""),
            "/brief": f"task text of {key}",
            "/prompt": f"prompt text of {key}",
            "/peek": f"text of {key}",
        }
        if url.path == "/call":
            return self._serve_call(key, texts["/call"])
        if url.path in texts:
            return self._json(200, {"id": key, "text": texts[url.path]})
        return self._json(404, {"error": "no such route"})

    def do_POST(self) -> None:  # http.server's name
        posted = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        type(self).requests.append(f"POST {self.path} {posted.get('path', '')}")
        time.sleep(1.2)  # a check takes a moment, so a second file can be opened while it runs
        lines = [
            {
                "line": 3,
                "rule": "CORE:S:0001",
                "message": "fixture finding",
                "severity": "warning",
                "title": "t",
                "category": "c",
                "file_level": False,
                "docs_url": None,
            }
        ]
        self._json(200, {"lines": lines})


@given('the served view says it picked "{picked}"')
def step_view_picked(context, picked):
    context.view_overrides = {"picked": picked}


@given('the bundled page is served over the "{name}" fixture view')
def step_serve_fixture(context, name):
    text = (FIXTURES / f"{name}.json").read_text(encoding="utf-8")
    handler = type(
        "Handler",
        (_FixtureHandler,),
        {
            "view_text": text,
            "requests": [],
            "bump_version": getattr(context, "bump_version", False),
            "overrides": getattr(context, "view_overrides", {}),
            "call_result": getattr(context, "call_result", True),
            "call_refused": getattr(context, "call_refused", False),
        },
    )
    context.handler = handler
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    context.add_cleanup(server.shutdown)
    context.add_cleanup(server.server_close)
    context.url = f"http://127.0.0.1:{server.server_address[1]}/"
    context.fixture = json.loads(text)


def _page(context, mode: str, width: int = 1440) -> dict | None:
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return None
    done = subprocess.run(
        [node, str(Path(__file__).resolve().parents[1] / "xray_page.mjs"), context.url, mode, str(width)],
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


@then('no two cards overlap at 1440 and at 925 pixels and no "+N running" text is drawn')
def step_no_card_overlap(context):
    for width in (1440, 925):
        seen = _page(context, "overlap", width)
        if seen is None:
            return
        assert seen["overlaps"] == 0, (width, seen)
        assert seen["running"] == 0, (width, seen)


@then("at 1440 and at 925 pixels no card overlaps another and every card sits 18 pixels above its launch on the spine")
def step_no_displaced_card(context):
    for width in (1440, 925):
        seen = _page(context, "p1layout", width)
        if seen is None:
            return
        assert seen["overlaps"] == 0, (width, seen)
        assert seen["running"] == 0, (width, seen)
        assert len(seen["launches"]) == 5, seen["launches"]  # two group cards and three lone cards
        for card in seen["launches"]:
            assert abs(card["top"] + 18 - card["launchY"]) < 0.6, (width, card)
            # the edge leaves the spine where the card is anchored
            assert abs(card["top"] + 18 - card["out"]) < 8, (width, card)


@then(
    "the bursts are collapsed group cards, a click expands one into rows of two members and a second click collapses it"
)
def step_group_toggle(context):
    seen = _page(context, "p1groups")
    if seen is None:
        return
    assert [g["key"] for g in seen["groupsBefore"]] == ["main:b1", "main:c1"], seen
    first = seen["groupsBefore"][0]
    assert "⇉ 6" in first["text"] and "in parallel" in first["text"] and "expand \u203a" in first["text"], first
    assert first["tiles"] == 6 and first["dashed"] == "dashed" and first["expanded"] == "false", first
    assert seen["membersBefore"] == [], seen
    members = seen["membersOpen"]
    assert len(members) == 6, seen
    tops = sorted({m["top"] for m in members})
    assert len(tops) == 3, members
    assert [sum(1 for m in members if m["top"] == t) for t in tops] == [2, 2, 2], members
    assert len({m["left"] for m in members if m["top"] == tops[0]}) == 2, members
    assert "⇉ fan-out · 6 subagents in parallel · " in seen["head"], seen["head"]
    assert seen["box"] is True and seen["groupCardsOpen"] == ["main:c1"], seen
    assert seen["arches"] == 6, seen
    assert seen["membersAfter"] == [] and seen["groupCardsAfter"] == 2, seen


@then("selecting a member of a collapsed group shows its group expanded until the user collapses it")
def step_group_selected(context):
    seen = _page(context, "p1select")
    if seen is None:
        return
    assert seen["before"] == 0, seen
    assert seen["after"] == 3 and seen["selected"] == "c2", seen
    assert seen["collapsed"] == 0 and seen["groupCard"] == 1, seen


@then(
    "a stretched segment shows a violet bar with its tooltip and the note, and no two ticks sit closer than 18 pixels"
)
def step_stretch_marked(context):
    seen = _page(context, "p1stretch")
    if seen is None:
        return
    assert seen["bars"], seen
    for bar in seen["bars"]:
        assert re.fullmatch(r"Scale stretched \d+\.\d\u00d7 between \d+:\d\d and \d+:\d\d", bar["title"]), bar
        assert bar["width"] == 2 and bar["colour"] == "rgb(165, 148, 255)", bar
    assert seen["note"] == "▍ time scale stretched where agents fan out", seen
    for ys in (seen["ticks"], seen["dense"]):
        assert len(ys) > 1 and all(b - a >= 18 for a, b in itertools.pairwise(ys)), ys


@then("drilling in three levels shows the collapsed breadcrumb and the parent strip of the direct parent")
def step_drill_in(context):
    seen = _page(context, "drill")
    if seen is None:
        return
    assert seen["crumbs"] == ["main agent", "/", "…", "/", "Fetch the spec"], seen
    assert seen["strip"] and seen["parent"] == "Survey the docs", seen
    assert seen["bars"] == ["a5c"] and seen["current"] == ["a5c"], seen
    assert seen["rootStrip"] is True, seen


@then("focusing a source rings exactly the nodes that had it and dims the rest, and a never-loaded source says so")
def step_focus_source(context):
    seen = _page(context, "focus")
    if seen is None:
        return
    nodes = {node["id"]: node for node in context.fixture["nodes"]}
    had = set(next(s for s in context.fixture["sources"] if s["id"] == "mcp:docs-server")["had_by"])
    burst = set(nodes["main"]["bursts"][0]["members"])  # drawn inside the collapsed group card, not as cards
    here = set(nodes["main"]["children"]) - burst
    assert {c["id"] for c in seen["mcp"] if c["ring"]} == had & here, seen["mcp"]
    assert {c["id"] for c in seen["mcp"] if c["dim"]} == here - had, seen["mcp"]
    assert [(g["ring"], g["dim"]) for g in seen["mcpGroup"]] == [(bool(had & burst), not had & burst)], seen["mcpGroup"]
    assert seen["mcpTop"] is ("main" in had), seen
    assert all(c["dim"] and not c["ring"] for c in seen["never"]), seen["never"]
    assert "Never loaded by any agent in this session." in seen["neverBanner"], seen
    assert seen["neverRow"] is True, seen


@then("toggling a layer removes that kind's slot chips, Sources section and source nodes at once")
def step_toggle_layer(context):
    seen = _page(context, "layer")
    if seen is None:
        return
    assert all(seen["before"][key] > 0 for key in ("chips", "sections", "nodes", "other")), seen
    assert seen["after"]["chips"] == seen["after"]["nodes"] == 0, seen
    assert seen["after"]["sections"] == seen["before"]["sections"], "the Sources list is an inventory, not a layer"
    assert seen["after"]["other"] == seen["before"]["other"], seen
    assert seen["again"] == seen["before"], seen


@then("the page draws no slot, toggle, section or station for a source kind the adapter omits")
def step_omitted_kinds(context):
    seen = _page(context, "omitted")
    if seen is None:
        return
    kept = [kind["key"] for kind in context.fixture["adapter"]["source_kinds"]]
    assert set(kept) == {"instructions", "memory", "skill"}, kept
    assert set(seen["toggles"]) == set(kept), seen
    assert set(seen["sections"]) <= set(kept) and set(seen["chips"]) <= set(kept), seen
    omitted = ("mcp:", ".claude/rules", "hook:")
    assert not [s for s in seen["stations"] if s.startswith(omitted)], seen
    assert seen["empty"] == 0 and "Stub Agent" in seen["adapter"], seen


@then("a compaction marker, a stopped subagent and a never-loaded source each render as specified")
def step_special_marks(context):
    seen = _page(context, "markers")
    if seen is None:
        return
    assert len(seen["compact"]) == 1 and seen["compact"][0].startswith("compacted · 529k → 53k"), seen["compact"]
    never = " ".join(seen["never"])
    assert "packages/cli/CLAUDE.md | not loaded" in never, seen["never"]
    assert any(row.startswith("cloudflare | not loaded") for row in seen["never"]), seen["never"]
    stopped = seen["stopped"]
    assert stopped["dashed"] and stopped["up"] == 0 and stopped["down"] == 1, stopped
    assert "stopped" in stopped["inspector"] and "Came back" not in stopped["inspector"], stopped
    assert stopped["animated"] == 1, stopped  # the out arch only: a stopped return never animates
    assert seen["returned"] == {"up": 1, "down": 1, "animated": 2}, seen["returned"]
    assert seen["reduced"] == "none", seen["reduced"]
    assert seen["bracket"].startswith("npm test -- --runInBand \u00d79"), seen["bracket"]


@then("a findings pill opens the file's findings at its hash and a source row links to its file")
def step_open_file(context):
    seen = _page(context, "file")
    if seen is None:
        return
    assert seen["pill"] == seen["hash"] == "#/file/CLAUDE.md", seen
    assert seen["name"] == "CLAUDE.md" and seen["peek"] == "text of CLAUDE.md", seen
    assert seen["backHash"].startswith("#/agent/main"), seen
    assert seen["row"] == "#/file/.claude/rules/rules-engine.md", seen


@then("the stub kind's cards are drawn by a stub renderer only the test serves, with no change to the canvas")
def step_stub_kind(context):
    seen = _page(context, "stub")
    if seen is None:
        return
    assert "stub" in seen["before"].lower() and "STUB" not in seen["before"], seen
    assert seen["after"] == "STUB Stub worker", seen
    assert seen["inspector"].startswith("Selected"), seen  # the right column describes any node kind
    assert seen["agentCard"] == 1, seen  # the agent kind still draws its own top node


@given("the served view carries a new version on every poll")
def step_bump_version(context):
    context.bump_version = True


@then("the page shows the view's own model, window, unknown facts, trigger words, notes, ratio and subagent counts")
def step_view_words(context):
    seen = _page(context, "words")
    if seen is None:
        return
    view = context.fixture
    assert view["model"] in seen["header"] and "1M window" in seen["header"], seen["header"]
    assert seen["unknown"] == "Not known: " + ", ".join(view["not_known"]) + ".", seen["unknown"]
    label = {t["key"]: t["label"] for t in view["adapter"]["triggers"]}
    assert any(label["session_start"] in title for title in seen["titles"]), seen["titles"]
    assert not any(
        old in title
        for title in seen["titles"]
        for old in ("at session start", "loaded by a path match", "inherited from its parent")
    ), seen["titles"]
    returned = next(n for n in view["nodes"] if n["id"] == "a1")["detail"]
    assert f"({round(returned['back_ratio'])}\u00d7 smaller)" in seen["returned"], seen["returned"]
    assert "smaller" not in seen["stopped"], seen["stopped"]
    main = next(n for n in view["nodes"] if n["id"] == "main")
    count = main["child_sources"]["mcp:docs-server"]
    assert f"{count} of {len(main['children'])} subagents here did" in seen["banner"], seen["banner"]
    assert "13 of 13 agents" in seen["claudeDetails"], seen["claudeDetails"]


@then("a kind the view reports absent says so from its fact, and an untyped node adds no filter button but still shows")
def step_absent_and_untyped(context):
    seen = _page(context, "absent")
    if seen is None:
        return
    assert seen["absent"] == ["No skills configured"], seen
    assert seen["typeButtons"] == [], seen
    assert seen["untypedCard"] is True, seen


@then("a file opened while another file's check runs is checked once that check ends")
def step_autocheck_queue(context):
    seen = _page(context, "autocheck")
    if seen is None:
        return
    assert seen["second"] and "fixture finding" in seen["second"], seen
    posts = [line.split(" ", 2)[2] for line in context.handler.requests if line.startswith("POST")]
    assert posts == ["CLAUDE.md", ".claude/rules/rules-engine.md"], posts


@then("each failing command's text is fetched once however many times the view changes")
def step_call_fetched_once(context):
    seen = _page(context, "calls")
    if seen is None:
        return
    assert seen["bracket"].startswith("npm test"), seen
    assert context.handler.views_served >= 3, context.handler.views_served
    calls = [r for r in context.handler.requests if r.startswith("/call")]
    assert calls and len(calls) == len(set(calls)), calls


@then("the inspector tiles open the peak and cost details, and every estimate has a tilde")
def step_inspector_panes(context):
    seen = _page(context, "panes")
    if seen is None:
        return
    view = context.fixture
    nodes = {n["id"]: n for n in view["nodes"]}
    comp = nodes["main"]["detail"]["composition"]
    reply = comp["replies"][comp["peak"]]
    total = reply[1]
    assert [t["label"] for t in seen["mainTiles"]] == ["Peak context", "Est. cost \u00b7 this agent"], seen["mainTiles"]
    peak_tile = seen["mainTiles"][0]
    assert peak_tile["value"] == _k1(total) and peak_tile["peek"] == "peak:main", peak_tile
    assert seen["mainTiles"][1]["peek"] == "cost:main", seen["mainTiles"]
    assert seen["peakOpen"]["title"] == f"{total:,} tokens", seen["peakOpen"]
    assert [c["key"] for c in seen["peakOpen"]["cats"]] == [
        c["key"] for c in view["adapter"]["composition"] if reply[5 + comp["keys"].index(c["key"])] > 0
    ], seen["peakOpen"]
    assert all(c["value"].startswith("~") for c in seen["peakOpen"]["cats"]), seen["peakOpen"]
    price = view["price_list"]
    assert f"{price['name']}, {price['as_of']}" in seen["costText"], seen["costText"]
    assert "~$" in seen["costText"], "instruction-file cost is an estimate"
    for key, text in (("a1", seen["a1Text"]), ("main", seen["mainText"])):
        node = nodes[key]
        values = [r["tokens_est"] for r in node["detail"]["in_context"]["rows"] if r["tokens_est"]]
        assert values, key
        for value in values:
            assert f"~{_k1(value)}" in text, (key, value)
    assert any(line.startswith("Parent had but didn't pass on:") for line in seen["withheld"]), seen["withheld"]


@then(
    "the Sources groups follow the adapter order with only the first open, expand and collapse all work, "
    "a long group shows four with a show-more, and focusing a source opens its group"
)
def step_source_groups(context):
    seen = _page(context, "groups")
    if seen is None:
        return
    order = [kind["key"] for kind in context.fixture["adapter"]["source_kinds"]]
    first = order[0]
    assert [g["kind"] for g in seen["initial"]] == order, seen["initial"]
    assert [g["kind"] for g in seen["initial"] if g["open"]] == [first], seen["initial"]
    assert all(not g["rows"] for g in seen["initial"] if g["kind"] != first), seen["initial"]
    assert all(g["open"] for g in seen["expanded"]), seen["expanded"]
    assert not any(g["open"] for g in seen["collapsed"]), seen["collapsed"]
    listed = [s for s in context.fixture["sources"] if s["kind"] == "agent"]
    agents = [s["id"] for s in sorted(listed, key=lambda s: s["availability"] != "loaded")]  # used items first
    assert len(agents) == 6, agents
    group = next(g for g in seen["agentOpen"] if g["kind"] == "agent")
    assert group["rows"] == agents[:4] and group["more"] == "Show 2 more", group
    group = next(g for g in seen["agentAll"] if g["kind"] == "agent")
    assert group["rows"] == agents and group["more"] == "Show fewer", group
    group = next(g for g in seen["agentFewer"] if g["kind"] == "agent")
    assert group["rows"] == agents[:4] and group["more"] == "Show 2 more", group
    assert not any(g["open"] for g in seen["closedAgain"]), seen["closedAgain"]
    focused = {g["kind"]: g for g in seen["focused"]}
    assert focused["agent"]["open"] and focused["agent"]["rows"] == agents, focused["agent"]
    assert [kind for kind, g in focused.items() if g["open"]] == ["agent"], focused
    instructions_sources = [s for s in context.fixture["sources"] if s["kind"] == "instructions"]
    findings = sum((s["findings"] or {}).get("count", 0) for s in instructions_sources)
    instructions = next(g for g in seen["initial"] if g["kind"] == "instructions")
    assert str(findings) in instructions["head"], instructions


@then(
    "a launched agent source lights exactly its subagents, a never-launched one lights nothing, "
    "the A chip is filled or outlined by count and the Sources panel has an eye per adapter kind"
)
def step_agent_sources(context):
    seen = _page(context, "agents")
    if seen is None:
        return
    sources = {s["id"]: s for s in context.fixture["sources"] if s["kind"] == "agent"}
    rows = seen["rows"]
    reviewer = rows[".claude/agents/reviewer.md"]
    assert reviewer["name"] == sources[".claude/agents/reviewer.md"]["name"], reviewer
    assert rows[".claude/agents/idle.md"]["who"] == "never launched", rows
    here = set(context.fixture["nodes"][0]["children"])
    lit = seen["lit"]
    assert set(lit[".claude/agents/reviewer.md"]) == set(sources[".claude/agents/reviewer.md"]["had_by"]) & here, lit
    assert lit[".claude/agents/idle.md"] == [] and lit[".claude/agents/idle.md top"] is False, lit
    chips = seen["chips"]

    def filled(name: str) -> bool:
        return bool({"on", "find"} & set(chips[name].split()))

    assert filled("a3") and filled("a4"), chips  # launched from a definition
    assert not filled("a1") and not filled("a5"), chips  # built-in types: outlined
    assert seen["toggles"] == [kind["key"] for kind in context.fixture["adapter"]["source_kinds"]], seen["toggles"]
    assert "agent" in seen["toggles"] and "hook" in seen["toggles"], seen["toggles"]


@then("an instructions source row shows its cost as an estimate and a source without one shows none")
def step_source_cost(context):
    seen = _page(context, "cost")
    if seen is None:
        return
    assert seen["claude"].endswith("~$0.01 · 21 findings") and seen["other"].endswith("~$0.01"), seen
    assert "$" not in seen["rule"], seen


def _points(text: str) -> list[tuple[float, float]]:
    return [(float(a), float(b)) for a, b in (pair.split(",") for pair in text.split())]


@then(
    "the spine is about 18 pixels wide each side at the peak reply, narrower at the first, "
    "its bands fill it in the adapter's order and no legend is drawn"
)
def step_spine_bands(context):
    seen = _page(context, "p4spine")
    if seen is None:
        return
    assert seen["legend"] is None, seen["legend"]
    outline = _points(seen["outline"])
    n = len(outline) // 2
    width = [outline[2 * n - 1 - k][0] - outline[k][0] for k in range(n)]  # the right edge is stored reversed
    main = next(node for node in context.fixture["nodes"] if node["id"] == "main")
    replies = main["detail"]["composition"]["replies"]
    peak = max(r[1] for r in replies)
    assert abs(max(width) / 2 - 18) < 0.2, max(width)
    assert abs(width[0] / 2 - (2 + 16 * replies[0][1] / peak)) < 0.2, (width[0], replies[0][1], peak)
    order = [c["key"] for c in context.fixture["adapter"]["composition"]]
    assert [b["key"] for b in seen["bands"]] == order, seen["bands"]
    shapes = [_points(b["points"]) for b in seen["bands"]]
    for k in range(n):
        total = sum(pts[2 * n - 1 - k][0] - pts[k][0] for pts in shapes)
        assert abs(total - width[k]) <= 1.0, (k, total, width[k])
    for left, right in itertools.pairwise(shapes):  # stacked left to right, each starting where the last ended
        assert all(abs(right[k][0] - left[2 * n - 1 - k][0]) <= 0.2 for k in range(n))
    assert {b["opacity"] for b in seen["bands"]} == {"0.5"}, seen["bands"]


@then("a hook stretch draws one pill with its count, and three close hook loads draw one pill naming all three")
def step_hook_and_merge(context):
    seen = _page(context, "p4stations")
    if seen is None:
        return
    hooks = [s for s in seen["stations"] if s["kind"] == "hook"]
    assert len(hooks) == 1, seen["stations"]
    assert hooks[0]["text"] == "H\u2193\u00d7120", hooks[0]
    assert not [
        s for s in seen["stations"] if s["source"].startswith("hook:") and s["kind"] not in ("hook", "merged")
    ], seen["stations"]
    merged = [s for s in seen["stations"] if s["kind"] == "merged"]
    assert len(merged) == 1 and merged[0]["tag"] == "BUTTON", seen["stations"]
    assert merged[0]["text"] == "3 hook loads", merged[0]
    lines = merged[0]["title"].split("\n")
    assert len(lines) == 3 and all(" \u00b7 ~" in line for line in lines), merged[0]
    assert merged[0]["label"].startswith("3 hook loads: "), merged[0]
    members = merged[0]["sources"].split()
    assert len(members) == 3 and merged[0]["source"] == members[0], merged[0]
    assert seen["pinned"], seen  # a click focuses the first member: the focus banner names it


@then("no handoff pill exists until an agent is selected, then its two show")
def step_handoff_pills(context):
    seen = _page(context, "p4pills")
    if seen is None:
        return
    assert seen["none"] == [], seen
    assert len(seen["selected"]) == 2 and seen["selected"][0].startswith("\u2193"), seen
    assert seen["selected"][1].startswith("\u2191"), seen
    assert len(seen["member"]) == 2, seen
    assert seen["cleared"] == [], seen


@then(
    "a long card title wraps to two lines, the subtitle has no type label and the title attribute holds the full name"
)
def step_card_title(context):
    seen = _page(context, "p4cards")
    if seen is None:
        return
    names = {node["id"]: node["name"] for node in context.fixture["nodes"]}
    cards = {c["id"]: c for c in seen["cards"]}
    long = cards["a2"]
    assert long["title"] == names["a2"] and long["name"] == names["a2"], long
    assert long["lines"] == 2, long  # an 80-character task wraps to two lines and ends there
    for card in cards.values():
        assert card["lines"] <= 2 and card["fits"] is True, card
        assert card["title"] == names[card["id"]], card
        assert re.fullmatch(r"\d+[ms]( \d+s)?", card["sub"]), card  # a duration, no type label


@then("a subagent launched at the start and an expanded fan-out box sit below the top card and touch no card")
def step_top_card_clear(context):
    for width in (1440, 925):
        seen = _page(context, "fxtop", width)
        if seen is None:
            return
        for state in (seen, seen["expanded"]):
            assert state["overlaps"] == 0 and state["boxHits"] == 0, (width, state)
        assert abs(seen["early"]["top"] + 18 - seen["early"]["launchY"]) < 0.6, (
            width,
            seen,
        )  # still at its launch time
        assert seen["boxTop"] >= seen["topBottom"] - 0.6, (width, seen)


@then("no station pill overlaps a card at 1440 and at 925 pixels")
def step_stations_clear(context):
    for width in (1440, 925):
        seen = _page(context, "overlap", width)
        if seen is None:
            return
        assert seen["stations"] > 0, (width, seen)
        assert seen["stationHits"] == 0, (width, seen)


@then("every group card line and its expand label sit inside the card at 1440 and at 925 pixels")
def step_group_text_inside(context):
    for width in (1440, 925):
        seen = _page(context, "fxgroup", width)
        if seen is None:
            return
        assert len(seen["groups"]) == 2, seen
        for group in seen["groups"]:
            assert group["expand"] and group["over"] == 0, (width, group)


@then("going up a level from a member of a collapsed group selects the member and shows its group expanded")
def step_up_opens_group(context):
    seen = _page(context, "fxup")
    if seen is None:
        return
    assert seen["before"] is False, seen
    assert seen["sel"] == "a1" and seen["afterUp"] is True, seen


@then(
    "a source row, the focus banner and a load station's tooltip print their token counts "
    "with a tilde and the word estimated"
)
def step_estimates_tilde(context):
    seen = _page(context, "fxbare")
    if seen is None:
        return
    assert seen["rows"] and seen["titles"], seen
    for text in seen["rows"]:
        assert re.search(r"~[\d.]+k? tok", text), text
    assert re.search(r"~[\d.]+k? each \(estimated\)", seen["focus"]), seen["focus"]
    for title in seen["titles"]:
        assert re.search(r"~[\d.]+k? loaded \(estimated\)", title), title


@then("the cost details say replies were not priced because no model was named, and list the models if any")
def step_unpriced_wording(context):
    seen = _page(context, "fxcost")
    if seen is None:
        return
    assert seen["main"] == ["2 replies not priced (no model named)"], seen
    assert seen["member"] == ["1 reply not priced: claude-unlisted-1"], seen


@then("the switcher lists the stub's sessions with start time, length and subagent count and marks the current one")
def step_switcher_lists(context):
    seen = _page(context, "switcher")
    if seen is None:
        return
    assert seen["button"] == "2026-10-28 09:14 UTC · 2h 0m · 5 subagents", seen["button"]
    assert seen["rows"] == [
        "2026-10-28 09:14 UTC · 2h 0m · 5 subagents",
        "2026-10-27 16:40 UTC · 1m 35s · 0 subagents",
        "2026-10-26 08:05 UTC · 1h 2m · 1 subagent",
    ], seen["rows"]
    assert seen["current"] == [seen["rows"][0]], seen["current"]


@then("no first prompt is requested until an entry's toggle is clicked, and then its text shows as text")
def step_first_prompt_lazy(context):
    seen = _page(context, "switcher")
    if seen is None:
        return
    assert seen["promptsBefore"] == [], seen["promptsBefore"]
    assert seen["promptsAfter"] == ["/first-prompt?session=sess-bbb"], seen["promptsAfter"]
    assert seen["promptText"] == "first prompt of sess-bbb", seen["promptText"]
    assert seen["promptAsText"] is True, "the first prompt must be a text node, not markup"
    assert seen["escapeClosed"] is True, "Escape must close the list"


@then("picking another entry reloads the page with that session and every session route it then calls carries it")
def step_pick_reloads(context):
    seen = _page(context, "switcher")
    if seen is None:
        return
    assert seen["search"] == "?session=sess-bbb", seen["search"]
    after = [r for r in seen["after"] if urlparse(r).path in SESSION_ROUTES]
    paths = {urlparse(r).path for r in after}
    assert {"/view", "/sessions", "/peek"} <= paths, paths
    missing = [r for r in after if parse_qs(urlparse(r).query).get("session") != ["sess-bbb"]]
    assert not missing, missing
    assert seen["footer"].startswith("Session sess-bbb."), seen["footer"]


@then("a notice names the view's adapter tool as the agent that did not say which session it is")
def step_notice_shows(context):
    seen = _page(context, "notice")
    if seen is None:
        return
    tool = context.fixture["adapter"]["tool"]
    assert seen["hidden"] is False and tool in seen["text"], seen
    assert "newest session" in seen["text"], seen


@then("no session notice is shown")
def step_notice_absent(context):
    seen = _page(context, "notice")
    if seen is None:
        return
    assert seen["hidden"] is True and seen["text"] == "", seen


SHARED_FILE = "shared/docs/CLAUDE.md"


@given(
    "a project whose instruction file sits under a symlinked folder that its config leaves out and the session loaded"
)
def step_symlinked_excluded_file(context):
    context.project = build_project(context.tmpdir / "proj").resolve()
    outside = context.tmpdir / "shared" / "canon"
    outside.mkdir(parents=True)
    (outside / "CLAUDE.md").write_text("# Canon\n\nsymlinked canon text\n", encoding="utf-8")
    (context.project / "shared").mkdir()
    (context.project / "shared" / "docs").symlink_to(outside)
    (context.project / ".ails").mkdir()
    (context.project / ".ails" / "config.yml").write_text("exclude_dirs:\n  - shared\n", encoding="utf-8")
    folder = context.home / ".claude" / "projects" / claude_project_folder_name(context.project)
    folder.mkdir(parents=True)
    shutil.copytree(FIXTURE / "session", folder / "session")
    rows = (FIXTURE / "session.jsonl").read_text(encoding="utf-8").replace("/work/proj", str(context.project))
    load = {
        "type": "attachment",
        "timestamp": "2026-10-30T20:11:30.000Z",
        "sessionId": SESSION_ID,
        "version": "2.1.308",
        "cwd": str(context.project),
        "attachment": {"type": "nested_memory", "path": str(context.project / SHARED_FILE), "displayPath": SHARED_FILE},
    }
    (folder / "session.jsonl").write_text(rows.rstrip("\n") + "\n" + json.dumps(load) + "\n", encoding="utf-8")


@then("the page shows that file's text and offers no check or fix for it")
def step_recorded_file_text(context):
    seen = _layout_script(context, "recorded", SHARED_FILE)
    if seen is None:
        return
    assert seen["ready"], "the page did not draw"
    assert seen["opened"], f"the page lists no source {SHARED_FILE}"
    assert "symlinked canon text" in seen["text"], seen
    assert "not a file this page lists" not in seen["dialog"], seen
    assert not [c for c in seen["controls"] if re.search(r"check|fix|finding", c, re.I)], seen["controls"]
    assert "Excluded by exclude_dirs `shared` in .ails/config.yml." in seen["dialog"], seen["dialog"]
    assert "Check and Fix are not offered: the file is a link to " in seen["dialog"], seen["dialog"]
    assert "outside the project." in seen["dialog"], seen["dialog"]


@given('the project\'s config excludes the folder "{folder}", which holds the loaded instruction file reading "{text}"')
def step_excluded_folder_with_load(context, folder, text):
    (context.project / folder).mkdir()
    (context.project / folder / "CLAUDE.md").write_text(f"# Scoped\n\n{text}\n", encoding="utf-8")
    (context.project / ".ails").mkdir()
    (context.project / ".ails" / "config.yml").write_text(f"exclude_dirs:\n  - {folder}\n", encoding="utf-8")


@then('"{source}" shows its text "{text}" and its check and fix buttons name exclude_dirs "{value}" in "{config}"')
def step_excluded_buttons_name_it(context, source, text, value, config):
    seen = _layout_script(context, "excluded", source)
    if seen is None:
        return
    assert seen["ready"] and seen["opened"], f"the page lists no source {source}: {seen}"
    assert text in seen["text"], seen
    assert [c for c in seen["dialogControls"] if re.search(r"check", c, re.I)], seen
    assert {"Check this file", "Fix this file"} <= set(seen["paneControls"]), seen
    named = f"exclude_dirs `{value}` in {config}"
    assert named in seen["dialogNote"] and named in seen["paneNote"], seen


@then(
    'with the details of "{source}" open on each tab, a session that grows redraws no panel whose content is unchanged'
)
def step_no_redraw_of_unchanged(context, source):
    node, chrome = shutil.which("node"), shutil.which("google-chrome") or shutil.which("chromium")
    if node is None or chrome is None:
        context.scenario.skip("SKIPPED LOUDLY: no node or Chrome on PATH, the page was not driven")
        return
    script = Path(__file__).resolve().parents[1] / "xray_flicker.mjs"
    proc = subprocess.Popen(  # pylint: disable=consider-using-with  # stopped by the scenario cleanup
        [node, str(script), context.url, source],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env={**os.environ, "CHROME_BIN": chrome},
    )
    context.add_cleanup(proc.kill)
    session = next((context.home / ".claude" / "projects").rglob("session.jsonl"))
    seen = []
    for turn in range(3):
        ready = proc.stdout.readline()
        assert ready.startswith("READY "), ready
        rows = session.read_text(encoding="utf-8").splitlines()
        later = json.loads(rows[-1])
        later["message"]["id"] = f"msg_grown_{turn}"
        later["timestamp"] = f"2026-10-30T20:12:{10 + turn:02d}.000Z"
        session.write_text("\n".join([*rows, json.dumps(later)]) + "\n", encoding="utf-8")
        proc.stdin.write("go\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        assert line.startswith("SEEN "), line
        seen.append(json.loads(line[len("SEEN ") :]))
    problems = []
    for tab in seen:
        assert tab["views"] > 0 and tab["text"], f"the page took no new view or showed no text on {tab['tab']}: {tab}"
        if tab["replaced"]:
            problems.append(f"{tab['tab']} tab: elements replaced with identical content: {tab['replaced']}")
        if tab["loading"] or tab["emptied"]:
            problems.append(
                f"{tab['tab']} tab: a text block reloaded: loading {tab['loading']}, empty {tab['emptied']}"
            )
    assert not problems, "\n".join(problems)
