"""Step definitions for the `ails check` named-target scenarios: named files and folders no agent loads,
capability-or-folder words, unknown capabilities and the JSON format version."""

from __future__ import annotations

from behave import given, then, when  # type: ignore[import-untyped]
from support import build_project, document, run_ails, write_claude

_PROSE = "# Review\n\nAlways review the code carefully before you approve a change.\n"
_CLAUDE = "# Project\n\n- Always run the tests before you commit.\n"
_PNG = b"\x89PNG\r\n\x1a\n"


def _output(context) -> str:
    return " ".join((context.result.stdout + context.result.stderr).split())


def _run(context, target: str, fmt: str, agent: str | None = None):
    args = ["check", target, "--format", fmt, "--offline"]
    if agent:
        args += ["--agent", agent]
    context.result = run_ails(context.project, *args, home=context.home)


@given('a git project with a "prompts/review.md" that no agent loads')
def step_unloaded_prompt(context):
    context.project = build_project(context.tmpdir)
    write_claude(context.project, _CLAUDE)
    (context.project / "prompts").mkdir()
    (context.project / "prompts" / "review.md").write_text(_PROSE, encoding="utf-8")


@given('a git project whose CLAUDE.md links "prompts/review.md" under generic_scanning')
def step_linked_prompt(context):
    context.project = build_project(context.tmpdir / "linked")
    write_claude(context.project, _CLAUDE + "\nSee [the review prompt](prompts/review.md).\n")
    (context.project / "prompts").mkdir()
    (context.project / "prompts" / "review.md").write_text(_PROSE, encoding="utf-8")
    (context.project / ".ails").mkdir()
    (context.project / ".ails" / "config.yml").write_text("generic_scanning: true\n", encoding="utf-8")


@given('a git project with an "assets" folder holding only an image')
def step_assets_project(context):
    context.project = build_project(context.tmpdir)
    write_claude(context.project, _CLAUDE)
    (context.project / "assets").mkdir()
    (context.project / "assets" / "logo.png").write_bytes(_PNG)


@given('a git copilot project with a "prompts" folder')
def step_copilot_project(context):
    context.project = build_project(context.tmpdir)
    (context.project / ".github").mkdir()
    (context.project / ".github" / "copilot-instructions.md").write_text(_CLAUDE, encoding="utf-8")
    (context.project / "prompts").mkdir()
    (context.project / "prompts" / "review.prompt.md").write_text(_PROSE, encoding="utf-8")
    (context.project / ".github" / "prompts").mkdir()
    (context.project / ".github" / "prompts" / "plan.prompt.md").write_text(_PROSE, encoding="utf-8")


@when('I run "ails check" on the named target "{target}" as {fmt}')
def step_run_named(context, target, fmt):
    _run(context, target, fmt)


@when('I run "ails check" with agent "{agent}" on the named target "{target}" as {fmt}')
def step_run_named_agent(context, target, agent, fmt):
    _run(context, target, fmt, agent)


@when('I run "ails check" with no target as {fmt}')
def step_run_no_target_fmt(context, fmt):
    context.result = run_ails(context.project, "check", "--format", fmt, "--offline", home=context.home)


@then('the json files map contains "{name}"')
def step_files_contain(context, name):
    assert name in document(context.result)["files"], sorted(document(context.result)["files"])


@then('the text run of "{name}" shows it in the Referenced panel')
def step_referenced_panel(context, name):
    context.result = run_ails(context.project, "check", name, "--offline", home=context.home)
    assert "Referenced" in _output(context), _output(context)


def _finding_set(context, name):
    entry = document(context.result)["files"].get(name)
    assert entry is not None, sorted(document(context.result)["files"])
    return sorted((f["rule"], f["line"], f["severity"]) for f in entry["findings"])


@when('I keep the finding set of "{name}"')
def step_keep_findings(context, name):
    context.kept_findings = _finding_set(context, name)


@then('the finding set of "{name}" equals the kept one')
def step_findings_equal(context, name):
    assert context.kept_findings, "the named run found nothing to compare"
    assert _finding_set(context, name) == context.kept_findings, (_finding_set(context, name), context.kept_findings)


@then('"{name}" is in the Referenced panel with no score of its own')
def step_referenced_unscored(context, name):
    data = document(context.result)
    assert name not in data["file_scores"], data["file_scores"]
    text = run_ails(context.project, "check", "--offline", home=context.home)
    out = " ".join(text.stdout.split())
    assert "Referenced" in out and name in out.split("Referenced", 1)[1], out


@then("the output does not ask to create a CLAUDE.md")
def step_no_create_hint(context):
    assert "Create a CLAUDE.md" not in _output(context), _output(context)


@then('the json not_evaluated lists "{name}" with the reason "{reason}"')
def step_not_evaluated_target(context, name, reason):
    items = document(context.result)["not_evaluated"]
    assert {"file": name, "reason": reason} in items, items


@then('the output names "{name}" as not checked and does not ask to create a CLAUDE.md')
def step_names_unchecked(context, name):
    out = _output(context)
    assert name in out and "not checked" in out, out
    assert "Create a CLAUDE.md" not in out and "Create an AGENTS.md" not in out, out


@then('the json notices say "{word}" was read as the capability, not the folder')
def step_json_clash(context, word):
    texts = [n["text"] for n in document(context.result)["notices"]]
    assert any(f"`{word}` is both a capability" in t and "read as the capability" in t for t in texts), texts


@then('the output says "{word}" was read as the capability, not the folder')
def step_text_clash(context, word):
    out = _output(context)
    assert f"`{word}` is both a capability" in out and "read as the capability" in out, out


@then("the json format_version is {version:d}")
def step_format_version(context, version):
    assert document(context.result)["format_version"] == version, list(document(context.result))
