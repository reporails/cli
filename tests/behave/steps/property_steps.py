"""Step definitions for the per-run output properties (`properties.feature`).

Every step reads the real binary's output: the `ails check` stdout/exit code in text, JSON and
`github`, and the MCP server's `validate` payload over stdio. Nothing runs in-process.
"""

from __future__ import annotations

import json

from behave import given, then, when  # type: ignore[import-untyped]
from support import (
    RULE_ID,
    fixture_project,
    github_finding_keys,
    json_finding_keys,
    rule_ids_in,
    run_ails,
    run_all_formats,
    text_finding_rules,
    write_config,
)

_CLI_FORMATS = ("text", "json", "github")
_STRICT_ARGS = {"text": ["-v"], "json": ["--format", "json"], "github": ["--format", "github"]}


def _stats(context) -> dict[str, int]:
    return json.loads(context.formats["json"].stdout)["stats"]


@given('the fixture project "{name}"')
def step_fixture(context, name):
    context.project = fixture_project(context.tmpdir, name)


@given("a project config that cannot be read")
def step_unreadable_config(context):
    write_config(context.project, "disabled_rules: [unclosed\n")


@when("I disable every rule the run reports")
def step_disable_every_rule(context):
    baseline = json.loads(
        run_ails(context.project, "check", "--format", "json", home=context.home, env=context.run_env).stdout
    )
    context.disabled = sorted(set(rule_ids_in(baseline["files"])))
    assert context.disabled, "the baseline run reported no rule, so nothing was disabled"
    write_config(context.project, "disabled_rules:\n" + "".join(f"  - {rule}\n" for rule in context.disabled))


@when("I run every output format")
def step_run_every_format(context):
    context.formats = run_all_formats(context.project, home=context.home, env=context.run_env)
    if "api" in context.scenario.tags:
        reached = (
            context.formats["mcp"].get("offline") is False
            and json.loads(context.formats["json"].stdout).get("offline") is False
        )
        assert reached, "the run did not reach the local api — the scenario would pass without it"


@then("text, JSON, GitHub and MCP carry one finding set")
def step_one_finding_set(context):
    runs = context.formats
    from_json = json_finding_keys(json.loads(runs["json"].stdout))
    assert from_json, "the run reported no finding, so the formats cannot be compared"
    assert json_finding_keys(runs["mcp"]) == from_json, "MCP and JSON carry different findings"
    assert github_finding_keys(runs["github"].stdout) == from_json, "github and JSON carry different findings"
    assert text_finding_rules(runs["text"].stdout) == sorted(rule for _, rule, *_ in from_json), (
        "text and JSON carry different findings"
    )


@then("the total equals m_probe plus client plus server in JSON and MCP")
def step_total_is_sum(context):
    for name, stats in (("json", _stats(context)), ("mcp", context.formats["mcp"]["stats"])):
        parts = stats["m_probe_count"] + stats["client_check_count"] + stats["server_diagnostic_count"]
        assert stats["total_findings"] == parts, (
            f"{name}: total {stats['total_findings']} != m_probe + client + server = {parts}"
        )
    assert _stats(context)["total_findings"] == context.formats["mcp"]["stats"]["total_findings"], (
        "JSON and MCP totals differ"
    )


@then("no output names a disabled rule")
def step_no_disabled_rule(context):
    runs, disabled = context.formats, set(context.disabled)
    named = {
        "json": set(rule_ids_in(json.loads(runs["json"].stdout))),
        "mcp": set(rule_ids_in(runs["mcp"])),
        "github": {rule for _, rule, *_ in github_finding_keys(runs["github"].stdout)},
        "text": set(RULE_ID.findall(runs["text"].stdout)),
    }
    leaked = {name: sorted(rules & disabled) for name, rules in named.items() if rules & disabled}
    assert not leaked, f"disabled rules still named: {leaked}"


@then("every command-line format exits as its findings say")
def step_exit_matches_findings(context):
    total = _stats(context)["total_findings"]
    expected_strict = 1 if total else 0
    for name in _CLI_FORMATS:
        plain = context.formats[name]
        assert plain.returncode == 0, f"{name}: a plain run exits 0, got {plain.returncode}\n{plain.stderr}"
        strict = run_ails(
            context.project, "check", *_STRICT_ARGS[name], "--strict", home=context.home, env=context.run_env
        )
        assert strict.returncode == expected_strict, (
            f"{name}: --strict over {total} findings exits {expected_strict}, got {strict.returncode}"
        )


@then("every command-line format exits 2 and reports no finding")
def step_unreadable_exits_two(context):
    for name in _CLI_FORMATS:
        result = context.formats[name]
        assert result.returncode == 2, f"{name}: an unreadable config exits 2, got {result.returncode}"
        assert not RULE_ID.search(result.stdout), f"{name}: an unreadable config still printed findings"


@then("MCP replies config_unreadable")
def step_mcp_config_unreadable(context):
    assert context.formats["mcp"].get("error") == "config_unreadable", f"got {context.formats['mcp'].get('error')!r}"
