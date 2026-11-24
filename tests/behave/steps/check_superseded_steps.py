"""Step definitions for the superseded-rule scenario: a rule the run superseded reports nothing."""

from __future__ import annotations

from behave import given, then  # type: ignore[import-untyped]
from support import build_project, document

_INSTRUCTION_RULES = {
    "CORE:C:0005",
    "CORE:C:0007",
    "CORE:C:0008",
    "CORE:C:0010",
    "CORE:C:0011",
    "CORE:C:0012",
    "CORE:C:0013",
    "CORE:C:0014",
    "CORE:C:0016",
    "CORE:C:0019",
    "CORE:C:0021",
    "CORE:C:0024",
    "CORE:C:0025",
    "CORE:C:0027",
    "CORE:C:0033",
    "CORE:C:0034",
    "CORE:C:0035",
    "CORE:C:0037",
    "CORE:S:0012",
    "CORE:S:0016",
}
_EXPECTED = {
    "CLAUDE.md": _INSTRUCTION_RULES,
    "AGENTS.md": _INSTRUCTION_RULES,
    ".claude/settings.json": {"CORE:G:0005"},
}


@given('a git project with CLAUDE.md, AGENTS.md and a ".claude/settings.json" with no hooks')
def step_project(context):
    context.project = build_project(context.tmpdir)
    (context.project / "CLAUDE.md").write_text(
        "# Project\n\nRun `uv run pytest` before committing.\n", encoding="utf-8"
    )
    (context.project / "AGENTS.md").write_text("# Project\n\nRun tests.\n", encoding="utf-8")
    (context.project / ".claude").mkdir()
    (context.project / ".claude" / "settings.json").write_text(
        '{\n  "permissions": {"allow": ["Bash(ls)"]}\n}\n', encoding="utf-8"
    )


def _rules(context) -> dict[str, list[str]]:
    files = document(context.result)["files"]
    return {name: [f["rule"] for f in entry["findings"]] for name, entry in files.items()}


@then('the json reports no finding for "{rule}"')
def step_none(context, rule):
    offending = [name for name, rules in _rules(context).items() if rule in rules]
    assert not offending, f"{rule} reported on {offending}"


@then("the json findings per file are the set the run reported before checks were read from parsed rules")
def step_set(context):
    got = {name: set(rules) for name, rules in _rules(context).items()}
    assert got == _EXPECTED, got
