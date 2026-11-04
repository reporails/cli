"""Step definitions for the x-ray hook and MCP demonstrations: a synthetic home, settings and transcript rows, and the
real `ails xray` binary over HTTP."""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

from behave import given, then  # type: ignore[import-untyped]
from steps.xray_steps import _get  # behave puts features/ on sys.path

from reporails_cli.core.discovery.agent_discovery import claude_project_folder_name

SESSION_ID = "11111111-2222-3333-4444-555555555555"
HOOK_COMMAND = "echo guard"
HOOK_OUTPUT = "guard-said-no-secret-text"
HOOK_ROW = "hook-row-0001"


def _session_file(context) -> Path:
    return context.home / ".claude" / "projects" / claude_project_folder_name(context.project) / "session.jsonl"


def _append_attachment(context, second: int, attachment: dict, **row: object) -> None:
    line = {
        "type": "attachment",
        "timestamp": f"2026-10-30T20:11:{second:02d}.000Z",
        "sessionId": SESSION_ID,
        "version": "2.1.308",
        "cwd": str(context.project),
        "attachment": attachment,
        **row,
    }
    with _session_file(context).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line) + "\n")


@given('the project\'s settings declare a PreToolUse hook running "{command}"')
def step_settings_hook(context, command):
    folder = context.project / ".claude"
    folder.mkdir(exist_ok=True)
    hook = {"type": "command", "command": command}
    settings = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [hook]}]}}
    (folder / "settings.json").write_text(json.dumps(settings), encoding="utf-8")


@given("the session recorded that hook running with some output")
def step_hook_firing(context):
    attachment = {
        "type": "hook_success",
        "hookName": "PreToolUse:Bash",
        "hookEvent": "PreToolUse",
        "toolUseID": "toolu_1",
        "command": HOOK_COMMAND,
        "exitCode": 0,
        "durationMs": 7,
        "stdout": HOOK_OUTPUT,
        "stderr": "",
        "content": "",
    }
    _append_attachment(context, 1, attachment, uuid=HOOK_ROW)


@given('an enabled plugin named "{plugin}" declares an MCP server of the same name that the user turned off here')
def step_plugin_server_off(context, plugin):
    root = context.home / "plugins" / plugin
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": plugin}), encoding="utf-8")
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {plugin: {"command": "uvx"}}}), encoding="utf-8")
    registry = context.home / ".claude" / "plugins"
    registry.mkdir(parents=True, exist_ok=True)
    installs = {"plugins": {f"{plugin}@{plugin}": [{"scope": "user", "installPath": str(root)}]}}
    (registry / "installed_plugins.json").write_text(json.dumps(installs), encoding="utf-8")
    account = {"projects": {str(context.project): {"disabledMcpServers": [f"plugin:{plugin}:{plugin}"]}}}
    (context.home / ".claude.json").write_text(json.dumps(account), encoding="utf-8")


@given('the session listed one tool of an MCP server named "{server}" that no file declares')
def step_tools_only_server(context, server):
    attachment = {
        "type": "deferred_tools_delta",
        "addedNames": [f"mcp__{server}__ping"],
        "addedLines": ["ping: a tool"],
        "removedNames": [],
    }
    _append_attachment(context, 2, attachment, uuid="listing-0001")


def _launched(context) -> tuple[str, str]:
    """The page's launch token and the session view it serves."""
    _, page = _get(context.url)
    token = re.search(r'name="xray-token" content="([^"]+)"', page)
    assert token, "the page carries no launch token"
    status, body = _get(context.url + "view", token.group(1))
    assert status == 200, status
    return token.group(1), body


def _source(body: str, kind: str, name: str) -> dict:
    found = next((s for s in json.loads(body)["sources"] if s["kind"] == kind and s["name"] == name), None)
    assert found is not None, f"no {kind} source named {name}"
    return found


@then("the hook's details name its command, its settings file and the firing's decision, exit code and output size")
def step_hook_details(context):
    _, body = _launched(context)
    detail = _source(body, "hook", "PreToolUse:Bash")["hook"]
    assert detail["commands"] == [{"command": HOOK_COMMAND, "declared_in": ".claude/settings.json"}], detail
    (firing,) = detail["firings"]
    assert (firing["decision"], firing["exit_code"], firing["chars"]) == ("ran", 0, len(HOOK_OUTPUT)), firing
    assert firing["duration_ms"] == 7 and firing["id"] == HOOK_ROW, firing


@then("the session view holds no output text and the hook output route returns it only when asked")
def step_hook_output_on_request(context):
    token, body = _launched(context)
    assert HOOK_OUTPUT not in body, "the view carries the hook's output text"
    url = context.url + "hook-output?" + urllib.parse.urlencode({"id": HOOK_ROW})
    assert _get(url)[0] == 403, "the route answers without the launch token"
    status, reply = _get(url, token)
    assert status == 200 and json.loads(reply)["text"] == HOOK_OUTPUT, (status, reply)
    status, _ = _get(context.url + "hook-output?id=no-such-row", token)
    assert status == 400, status


@then('the MCP group lists "{plugin}" as that plugin\'s server turned off in this project')
def step_mcp_plugin_off(context, plugin):
    _, body = _launched(context)
    detail = _source(body, "mcp", plugin)["mcp"]
    assert detail["plugin"] == plugin and detail["state"] == "turned_off", detail
    assert detail["declared_in"] and detail["declared_in"].endswith(".mcp.json"), detail


@then('the MCP group lists "{server}" as connected with one tool and no plugin')
def step_mcp_tools_only(context, server):
    _, body = _launched(context)
    source = _source(body, "mcp", server)
    assert source["mcp"]["plugin"] is None and source["mcp"]["state"] == "connected", source["mcp"]
    assert source["tools"] == [[f"mcp__{server}__ping", 0]] and source["mcp"]["declared_in"] is None, source
