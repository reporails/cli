"""Step definitions for the heal-regression scenarios: a seeded heal record read by a plain `ails check`."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from behave import given, then  # type: ignore[import-untyped]
from support import build_project, document, run_ails

_LINE = "Since the last heal:"
_BROKEN = "# Rules\n\n- Always run tests before commit.\n\nSee [guide](missing/guide.md) and @nothere.md\n"
_RULE = "---\npaths:\n  - 'src/**'\n---\n\n# Style\n\n- Keep lines short.\n\nSee [guide](missing/other.md)\n"


def _rule_counts(context) -> dict[str, dict[str, int]]:
    """Per project-relative file, how many findings each rule has in a plain run of the project."""
    run = run_ails(context.project, "check", "--offline", "--format", "json", home=context.home)
    counts: dict[str, dict[str, int]] = {}
    for file, record in document(run).get("files", {}).items():
        for finding in record.get("findings", []):
            per_rule = counts.setdefault(file, {})
            per_rule[finding["rule"]] = per_rule.get(finding["rule"], 0) + 1
    return counts


@given("a git project with two files that have findings")
def step_two_files(context):
    context.project = build_project(context.tmpdir)
    (context.project / "CLAUDE.md").write_text(_BROKEN, encoding="utf-8")
    rules = context.project / ".claude" / "rules"
    rules.mkdir(parents=True)
    (rules / "style.md").write_text(_RULE, encoding="utf-8")
    context.counts = _rule_counts(context)
    assert "CLAUDE.md" in context.counts, context.counts
    assert ".claude/rules/style.md" in context.counts, context.counts


@given('a heal record that holds "{regressed}" with no findings and "{steady}" as the run finds it')
def step_seed_record(context, regressed, steady):
    context.regressed, context.steady = regressed, steady
    healed_at = datetime.now(UTC).isoformat()
    record = {
        "files": {
            regressed: {"score": None, "rules": {}, "healed_at": healed_at},
            steady: {"score": None, "rules": context.counts[steady], "healed_at": healed_at},
        }
    }
    path = context.project / ".ails" / "reports" / "heal-latest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record), encoding="utf-8")


def _lines(context) -> list[str]:
    return [line.strip() for line in (context.result.stdout + context.result.stderr).splitlines() if _LINE in line]


@then('the output has one "Since the last heal:" line, for "{name}", naming its findings back')
def step_one_line(context, name):
    lines = _lines(context)
    assert len(lines) == 1, lines
    assert name in lines[0] and "findings back:" in lines[0], lines[0]
    assert any(f"{rule} +{n}" in lines[0] for rule, n in context.counts[name].items()), lines[0]


@then('the output has no "Since the last heal:" line')
def step_no_line(context):
    assert not _lines(context), _lines(context)


@then('the JSON "heal_regressions" names only "{name}" with the rules that grew')
def step_json_names(context, name):
    entries = document(context.result)["heal_regressions"]
    assert [e["file"] for e in entries] == [name], entries
    assert entries[0]["rules"] == context.counts[name], entries


@then('the JSON "heal_regressions" is empty')
def step_json_empty(context):
    assert document(context.result)["heal_regressions"] == []
