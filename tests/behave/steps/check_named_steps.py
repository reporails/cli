"""Step definitions for the `ails check` named-target scenarios: named files and folders no agent loads,
capability-or-folder words, unknown capabilities and the JSON format version."""

from __future__ import annotations

from behave import given, then, when  # type: ignore[import-untyped]
from support import build_project, document, run_ails, write_claude

_PROSE = "# Review\n\nAlways review the code carefully before you approve a change.\n"
_CLAUDE = "# Project\n\n- Always run the tests before you commit.\n"
_PNG = b"\x89PNG\r\n\x1a\n"
# A prompt with a link to a file that does not exist: a finding every markdown file gets, loaded or not.
_PROMPT = _PROSE + "\nSee [the notes](notes.md).\n"
_PATH_SCOPED_RULES = ("CLAUDE:S:0012", "CORE:S:0038", "CORE:S:0026")


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
    (context.project / "prompts" / "review.md").write_text(_PROMPT, encoding="utf-8")


@given('a git project whose CLAUDE.md links "prompts/review.md" under generic_scanning')
def step_linked_prompt(context):
    context.project = build_project(context.tmpdir / "linked")
    write_claude(context.project, _CLAUDE + "\nSee [the review prompt](prompts/review.md).\n")
    (context.project / "prompts").mkdir()
    (context.project / "prompts" / "review.md").write_text(_PROMPT, encoding="utf-8")
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


@given('a git project that sets exclude_dirs to "prompts", a folder holding "review.md"')
def step_excluded_prompts(context):
    context.project = build_project(context.tmpdir)
    write_claude(context.project, _CLAUDE)
    (context.project / "prompts").mkdir()
    (context.project / "prompts" / "review.md").write_text(_PROSE, encoding="utf-8")
    (context.project / ".ails").mkdir()
    (context.project / ".ails" / "config.yml").write_text("exclude_dirs: [prompts]\n", encoding="utf-8")


@given('a git project whose CLAUDE.md imports "docs/extra.md" under generic_scanning')
def step_imported_doc(context):
    context.project = build_project(context.tmpdir)
    write_claude(context.project, _CLAUDE + "\n@docs/extra.md\n")
    (context.project / "docs").mkdir()
    (context.project / "docs" / "extra.md").write_text(_PROMPT, encoding="utf-8")
    (context.project / ".ails").mkdir()
    (context.project / ".ails" / "config.yml").write_text("generic_scanning: true\n", encoding="utf-8")


@given('a git project with a "prompts/Up.MD" file')
def step_upper_md(context):
    context.project = build_project(context.tmpdir)
    write_claude(context.project, _CLAUDE)
    (context.project / "prompts").mkdir()
    (context.project / "prompts" / "Up.MD").write_text(_PROSE, encoding="utf-8")


@given("a git copilot project with no skill files")
def step_copilot_no_skills(context):
    context.project = build_project(context.tmpdir)
    (context.project / ".github").mkdir()
    (context.project / ".github" / "copilot-instructions.md").write_text(_CLAUDE, encoding="utf-8")


@when('I run "ails check" on the named target "{target}" as {fmt}')
def step_run_named(context, target, fmt):
    _run(context, target, fmt)


@when('I run "ails check" with agent "{agent}" on the named target "{target}" as {fmt}')
def step_run_named_agent(context, target, agent, fmt):
    _run(context, target, fmt, agent)


@when('I run "ails check" with no target as {fmt}')
def step_run_no_target_fmt(context, fmt):
    context.result = run_ails(context.project, "check", "--format", fmt, "--offline", home=context.home)


@given('a git project with a "docs" folder holding "guide.md"')
def step_docs_folder(context):
    context.project = build_project(context.tmpdir)
    write_claude(context.project, _CLAUDE)
    (context.project / "docs").mkdir()
    (context.project / "docs" / "guide.md").write_text(_PROMPT, encoding="utf-8")


@when('I run "ails check" on the named targets "{first}" and "{second}" as {fmt}')
def step_run_two_named(context, first, second, fmt):
    context.result = run_ails(context.project, "check", first, second, "--format", fmt, "--offline", home=context.home)


@then("the exit code is {code:d}")
def step_exit_code(context, code):
    assert context.result.returncode == code, (context.result.returncode, _output(context))


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


@then('no path-scoped rule file rule is reported for "{name}"')
def step_no_path_scoped_rule(context, name):
    rules = {rule for rule, _, _ in _finding_set(context, name)}
    assert not rules & set(_PATH_SCOPED_RULES), sorted(rules)


@given('a git project whose ".claude" folder holds a rule, a worktree copy and a plan file')
def step_claude_folder_working_copies(context):
    context.project = build_project(context.tmpdir)
    write_claude(context.project, _CLAUDE)
    for rel in (".claude/rules/style.md", ".claude/worktrees/w1/README.md", ".claude/worktrees/w1/docs/guide.md"):
        (context.project / rel).parent.mkdir(parents=True, exist_ok=True)
        (context.project / rel).write_text(_PROSE, encoding="utf-8")
    (context.project / ".claude" / "plans").mkdir()
    (context.project / ".claude" / "plans" / "p.md").write_text(_PROSE, encoding="utf-8")


@then('the json files map holds no file under "{first}" or "{second}"')
def step_files_not_under(context, first, second):
    files = sorted(document(context.result)["files"])
    assert not [f for f in files if f.startswith((first, second))], files


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


@then('the text run of "{name}" shows it as Imported and not as an unlisted file')
def step_imported_panel(context, name):
    context.result = run_ails(context.project, "check", name, "--offline", home=context.home)
    out = _output(context)
    assert "Imported" in out and "Referenced" not in out, out
    assert "is not an instruction file" not in out and "is not loaded by" not in out, out


@then('the output names "{name}" as not checked')
def step_names_unchecked_only(context, name):
    out = _output(context)
    assert name in out and "not checked" in out, out


@then('the output says the markdown of "{name}" is left out by exclude_dirs')
def step_excluded_text(context, name):
    out = _output(context)
    assert f"{name} not checked" in out and "exclude_dirs" in out and "holds no markdown" not in out, out


@then("the output does not ask to create an instruction file")
def step_no_create_any(context):
    assert "to get started" not in _output(context), _output(context)


@given('a git project whose "linked" folder links to a folder outside it that holds "notes.md"')
def step_linked_folder_outside(context):
    context.project = build_project(context.tmpdir / "proj")
    write_claude(context.project, _CLAUDE)
    outside = context.tmpdir / "outside" / "ext"
    outside.mkdir(parents=True)
    (outside / "notes.md").write_text(_PROMPT, encoding="utf-8")
    (context.project / "linked").symlink_to(outside, target_is_directory=True)


@then('the json checks a file named "{name}" and lists "{target}" as not checked for no reason')
def step_checks_file_not_listed(context, name, target):
    doc = document(context.result)
    assert any(key.endswith(name) for key in doc["files"]), sorted(doc["files"])
    assert target not in [item.get("file") for item in doc["not_evaluated"]], doc["not_evaluated"]


_BROKEN_HOOKS = (
    '{"hooks": {"PretoolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}]}}\n'
)


@given('a project "proj" elsewhere with a ".claude/settings.json" and a folder outside it')
def step_other_project_settings(context):
    proj = context.tmpdir / "elsewhere" / "proj"
    (proj / ".claude").mkdir(parents=True)
    write_claude(proj, _CLAUDE)
    (proj / ".claude" / "settings.json").write_text(_BROKEN_HOOKS, encoding="utf-8")
    context.config_file = str((proj / ".claude" / "settings.json").resolve())
    context.project = context.tmpdir / "outside"
    context.project.mkdir()


@given('a git project and a user-level "~/.claude/settings.json" beside a user CLAUDE.md')
def step_user_settings(context):
    (context.home / ".claude").mkdir(parents=True)
    write_claude(context.home / ".claude", _CLAUDE)
    (context.home / ".claude" / "settings.json").write_text(_BROKEN_HOOKS, encoding="utf-8")
    context.config_file = str(context.home / ".claude" / "settings.json")
    context.project = build_project(context.tmpdir)
    write_claude(context.project, _CLAUDE)


@when('I run "ails check" on that settings file as {fmt}')
def step_run_config_file(context, fmt):
    _run(context, context.config_file, fmt)


@then('the json not_evaluated lists that settings file with the reason "{reason}"')
def step_config_not_evaluated(context, reason):
    doc = document(context.result)
    assert doc["files"] == {}, sorted(doc["files"])
    assert doc["not_evaluated"] == [{"file": context.config_file, "reason": reason}], doc["not_evaluated"]


@then("the output says to run ails check in that project's folder")
def step_points_at_its_project(context):
    out = _output(context)
    assert f"{context.config_file} not checked:" in out, out
    assert "run ails check in that project's folder" in out, out


@then('the json checks "{name}" and lists nothing as not checked')
def step_checked_nothing_unlisted(context, name):
    doc = document(context.result)
    assert name in doc["files"], sorted(doc["files"])
    assert not [i for i in doc["not_evaluated"] if "reason" in i], doc["not_evaluated"]


@given('an empty git project "{name}" and a git project beside it to run from')
def step_empty_project_beside(context, name):
    context.empty_project = build_project(context.tmpdir / name)
    context.project = build_project(context.tmpdir / "runner")
    write_claude(context.project, _CLAUDE)


@when('I run "ails check" on the empty project by its path as {fmt}')
def step_run_empty_by_path(context, fmt):
    _run(context, str(context.empty_project), fmt)


@given('an empty git project with a "docs" folder holding only "readme.txt"')
def step_empty_project_docs(context):
    context.project = build_project(context.tmpdir)
    (context.project / "docs").mkdir()
    (context.project / "docs" / "readme.txt").write_text("hello\n", encoding="utf-8")


@then("the output says no instruction files were found and asks to create an AGENTS.md")
def step_usual_empty_run(context):
    out = _output(context)
    assert "No instruction files found." in out and "Level: L0" in out, out
    assert "Create an AGENTS.md to get started." in out, out


@then("the output lists no target as not checked")
def step_nothing_unchecked(context):
    assert "not checked" not in _output(context), _output(context)


@then("the json not_evaluated is empty")
def step_json_not_evaluated_empty(context):
    assert document(context.result)["not_evaluated"] == [], document(context.result)["not_evaluated"]
