"""Step definitions for the `ails check` project-root scenarios: linked files, no target in a
`~/.claude` folder, and the not-listed notice inside the folder the command runs in."""

from __future__ import annotations

from behave import given, then, when  # type: ignore[import-untyped]
from support import build_project, document, run_ails

_BODY = "# Rules\n\n- Always run tests before commit.\n- Never commit secrets.\n"
_RULE = "---\npaths:\n  - 'src/**'\n---\n\n" + _BODY


def _output(context) -> str:
    return context.result.stdout + context.result.stderr


@given('a git project whose ".claude/rules/style.md" links to a file outside it')
def step_linked_rule(context):
    context.project = build_project(context.tmpdir)
    shared = context.tmpdir / "shared"
    shared.mkdir()
    (shared / "style.md").write_text(_RULE, encoding="utf-8")
    rules = context.project / ".claude" / "rules"
    rules.mkdir(parents=True)
    (rules / "style.md").symlink_to(shared / "style.md")


@when('I run "ails check" on the linked file from the project folder')
def step_run_linked(context):
    context.result = run_ails(context.project, "check", ".claude/rules/style.md", "--format", "json", home=context.home)


@given("a home rule file that links to a dotfiles folder")
def step_linked_home_rule(context):
    dotfiles = context.tmpdir / "dotfiles"
    dotfiles.mkdir()
    (dotfiles / "style.md").write_text(_RULE, encoding="utf-8")
    rules = context.home / ".claude" / "rules"
    rules.mkdir(parents=True)
    (rules / "style.md").symlink_to(dotfiles / "style.md")
    context.project = build_project(context.tmpdir)


@when('I run "ails check" on the linked home rule file from a project folder')
def step_run_linked_home(context):
    target = str(context.home / ".claude" / "rules" / "style.md")
    context.result = run_ails(context.project, "check", target, "--format", "json", home=context.home)


@then('the run checked "{name}" relative to its project root')
def step_checked_relative(context, name):
    paths = document(context.result).get("capability_paths", [])
    assert paths == [name], paths


@then("the output does not say the file is not an instruction file")
def step_no_unlisted_notice(context):
    assert "is not an instruction file" not in _output(context), _output(context)


@when('I run "ails check" with no target from the home "{folder}" folder')
def step_run_no_target(context, folder):
    context.result = run_ails(context.home / ".claude" / folder, "check", "--format", "json", home=context.home)


@given('a git project with a "docs/guide.md" that is not an instruction file')
def step_unlisted_guide(context):
    context.project = build_project(context.tmpdir)
    (context.project / "docs").mkdir()
    (context.project / "docs" / "guide.md").write_text("# Guide\n\nAlways run tests.\n", encoding="utf-8")


@then('the notice says "{name}" is not an instruction file of this project, with no advice to move')
def step_in_folder_notice(context, name):
    output = " ".join(_output(context).split())
    assert f"{name} is not an instruction file of this project." in output, output
    assert "run ails check in that project's folder" not in output, output
