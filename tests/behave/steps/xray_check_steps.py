"""Step definitions for the x-ray page's check route reaching a file written while the page is open."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from behave import then, when  # type: ignore[import-untyped]
from support import run_ails  # behave puts features/ on sys.path
from xray_steps import SESSION_ID, _get


def _record_load(context, path: str) -> None:
    log = next((context.home / ".claude" / "projects").glob("*/session.jsonl"))
    load = {
        "type": "attachment",
        "timestamp": "2026-10-30T20:11:30.000Z",
        "sessionId": SESSION_ID,
        "version": "2.1.308",
        "cwd": str(context.project),
        "attachment": {"type": "nested_memory", "path": str(context.project / path), "displayPath": path},
    }
    log.write_text(log.read_text(encoding="utf-8").rstrip("\n") + "\n" + json.dumps(load) + "\n", encoding="utf-8")


def _token(context) -> str:
    token = re.search(r'name="xray-token" content="([^"]+)"', _get(context.url)[1])
    assert token, "the page carries no launch token"
    return token.group(1)


def _check_reply(context, path: str) -> dict:
    request = urllib.request.Request(
        context.url + "check",
        data=json.dumps({"path": path}).encode(),
        headers={
            "x-xray-token": _token(context),
            "Origin": context.url.rstrip("/"),
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as reply:
            return json.loads(reply.read())
    except urllib.error.HTTPError as error:
        raise AssertionError(f"the page refused the check of {path}: {error.code} {error.read().decode()}") from error


@when('the page is asked to check "{path}"')
def step_page_check(context, path):
    context.page_findings = {(line["rule"], line["line"]) for line in _check_reply(context, path)["lines"]}


@when('the file "{path}" is written and loaded by the session, reading "{text}"')
def step_write_file(context, path, text):
    target = context.project / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text + "\n", encoding="utf-8")
    _record_load(context, path)
    status, _ = _get(context.url + "view", _token(context))  # the page's poll reads the grown transcript
    assert status == 200, status


@then('the page\'s findings for "{path}" are not empty')
def step_page_not_empty(context, path):
    assert context.page_findings, f"the page's check of {path} returned no findings"


@then('they are the rule and line pairs "ails check {path} --offline --format json" reports for it')
def step_same_as_cli(context, path):
    done = run_ails(context.project, "check", path, "--offline", "--format", "json", home=context.home)
    expected = {(f["rule"], f["line"]) for f in json.loads(done.stdout)["files"][path]["findings"]}
    assert expected, f"the command reported no findings for {path}"
    assert context.page_findings == expected, (sorted(context.page_findings), sorted(expected))
