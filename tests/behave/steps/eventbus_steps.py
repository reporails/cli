"""Step definitions for the event bus demonstrations: the real `ails hook` and `ails events` binary."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from behave import given, then, when  # type: ignore[import-untyped]
from support import AILS_BIN, run_ails  # behave puts features/ on sys.path

from tests.suite_env import suite_env

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "claude_payloads.jsonl"
KINDS = {
    "SessionStart": "session_start",
    "UserPromptSubmit": "prompt_submit",
    "PreToolUse": "pre_tool",
    "PostToolUse": "post_tool",
    "Stop": "stop",
    "SubagentStop": "subagent_stop",
    "PreCompact": "pre_compact",
    "PostCompact": "post_compact",
    "SessionEnd": "session_end",
}


def _hook(context, stdin: str, *args: str) -> subprocess.CompletedProcess[str]:
    assert AILS_BIN is not None, "`ails` console script not on PATH (run via `uv run behave`)"
    env = {**suite_env(os.environ), "HOME": str(context.home), "USERPROFILE": str(context.home)}
    return subprocess.run(
        [str(AILS_BIN), "hook", *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        env=env,
        cwd=str(context.tmpdir),
    )


def _events(context, session: str, *args: str) -> dict:
    result = run_ails(context.tmpdir, "events", "--session", session, "-f", "json", *args, home=context.home)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _log_size(context) -> int:
    return (context.home / ".reporails" / "xray" / f"{context.session}.events.jsonl").stat().st_size


@given("the recorded Claude Code session payloads")
def step_payloads(context):
    context.payloads = FIXTURE.read_text(encoding="utf-8").splitlines()
    assert len(context.payloads) == 15
    context.session = json.loads(context.payloads[0])["session_id"]
    context.hook_runs = []


@given("the event store location is a regular file")
def step_store_is_file(context):
    xray = context.home / ".reporails" / "xray"
    xray.parent.mkdir(parents=True, exist_ok=True)
    xray.write_text("not a folder", encoding="utf-8")


@when('every payload is piped into "ails hook --agent claude" in order')
def step_pipe_all(context):
    context.hook_runs = [_hook(context, line, "--agent", "claude") for line in context.payloads]


@when('the text "{text}" is piped into "ails hook"')
def step_pipe_text(context, text):
    context.hook_runs = [_hook(context, text)]


@then("every hook call exited 0 with nothing on stdout")
def step_hook_quiet(context):
    assert context.hook_runs, "no hook call ran"
    for run in context.hook_runs:
        assert run.returncode == 0, run.stderr
        assert run.stdout == "", run.stdout


@then('"ails events" returns the session\'s records in order with the right kinds and tool-use ids')
def step_events_all(context):
    body = _events(context, context.session)
    sent = [json.loads(line) for line in context.payloads]
    got = body["records"]
    assert len(got) == 15 and body["next"] == _log_size(context), body["next"]
    assert [r["event"] for r in got] == [KINDS[p["hook_event_name"]] for p in sent]
    assert [r["tool_use_id"] for r in got] == [p.get("tool_use_id") for p in sent]
    assert all(r["session_id"] == context.session for r in got)


@when('the first 10 payloads are piped into "ails hook --agent claude" in order')
def step_pipe_first(context):
    context.hook_runs = [_hook(context, line, "--agent", "claude") for line in context.payloads[:10]]


@when('"ails events" is run and the "next" it printed is kept')
def step_keep_next(context):
    body = _events(context, context.session)
    assert len(body["records"]) == 10, body["records"]
    context.kept_next = body["next"]


@when('the remaining payloads are piped into "ails hook --agent claude" in order')
def step_pipe_rest(context):
    context.hook_runs += [_hook(context, line, "--agent", "claude") for line in context.payloads[10:]]


@then('"ails events --after" the kept "next" returns only the last 5 records')
def step_events_after(context):
    context.resumed = _events(context, context.session, "--after", str(context.kept_next))
    sent = [json.loads(line) for line in context.payloads[10:]]
    assert [r["event"] for r in context.resumed["records"]] == [KINDS[p["hook_event_name"]] for p in sent]


@then('the "next" it printed is the byte size of the session\'s log')
def step_next_is_size(context):
    assert context.resumed["next"] == _log_size(context), context.resumed["next"]


@then('"ails events" for the session "{session}" shows a refusal record')
def step_refusal(context, session):
    records = _events(context, session)["records"]
    assert [r["event"] for r in records] == ["refusal"], records
    assert records[0]["refusal"]


@when('"ails events --after -1" is run for the session')
def step_negative_after(context):
    context.negative = run_ails(
        context.tmpdir, "events", "--session", context.session, "--after", "-1", "-f", "json", home=context.home
    )


@then("the command exited 2 with no JSON on stdout")
def step_exit_two(context):
    assert context.negative.returncode == 2, (context.negative.returncode, context.negative.stderr)
    assert context.negative.stdout.strip() == "", context.negative.stdout
