"""Step definitions for the `ails check` behavioral demonstrations.

Builds a real git project on disk and drives the REAL ``ails check`` console
script via subprocess (through ``features/support.py``) — the full composed
pipeline: CLI arg parsing, discovery, mapping, classification, scoring, exit-code
derivation, and both the text and JSON formatters. No in-process ``CliRunner``.
"""

from __future__ import annotations

import subprocess

from behave import given, then, when  # type: ignore[import-untyped]
from support import (  # behave puts features/ on sys.path
    build_project,
    document,
    findings,
    run_ails,
    write_claude,
    write_config,
)

# A sparse instruction file with real error findings; the rich rewrite carries more
# structure, specificity, and backticked constructs, so the finding set changes.
_SPARSE = "# Rules\n\n- Always run tests before commit.\n- Never commit secrets.\n"
_RICH = (
    "# Project rules\n\n## Testing\n\n"
    "- Always run `pytest -q` before every `git commit`; fix failures first.\n"
    "- Keep coverage above the threshold in `pyproject.toml`.\n\n## Security\n\n"
    "- Never commit `.env`, `secrets.yaml`, or API keys to the repo.\n"
    "- Rotate credentials via the `scripts/rotate.sh` helper.\n\n## Layout\n\n"
    "- Source lives in `src/`; tests in `tests/`.\n"
)

# The finding-tuple wire contract every JSON finding must carry.
_TUPLE_KEYS = ("line", "severity", "rule", "category", "message")


def _snapshot(context):
    """A stable, order-independent snapshot of the last json run's FULL findings.

    Sorted tuple of the six contract fields per finding — so a determinism check
    reddens on ANY per-finding non-determinism (a flipped severity, a moved line,
    a reordered set), not only on the set of rule ids. Values are ``repr``-coerced,
    not ``str``: a missing key sorts to a stable ``"None"`` instead of raising a
    TypeError when ``sorted`` compares a None against a str, AND the repr keeps the
    type distinct — ``10`` (int) reprs as ``10`` while ``"10"`` (str) reprs as
    ``'10'``, so a formatter that starts emitting the ``line`` number as a string
    still reddens the guard, and a dropped key (``None`` -> ``"None"``) no longer
    collides with a finding whose value is the literal string ``"None"`` (-> ``"'None'"``).
    """
    return tuple(sorted(tuple(repr(f.get(k)) for k in _TUPLE_KEYS) for f in findings(context.result)))


@given("a git project whose CLAUDE.md has error findings")
def step_project_with_errors(context):
    context.project = build_project(context.tmpdir)
    context.runs = []  # ordered full-finding snapshots, one per json run
    write_claude(context.project, _SPARSE)


@when("the CLAUDE.md is rewritten to a richer instruction set")
def step_rewrite_richer(context):
    write_claude(context.project, _RICH)


@when('I run "{command}"')
def step_run(context, command):
    parts = command.split()
    assert parts[0] == "ails", f"scenario drives the ails binary, got {parts[0]!r}"
    context.result = run_ails(context.project, *parts[1:], home=context.home)
    if "json" in parts:
        if not hasattr(context, "runs") or context.runs is None:
            context.runs = []
        context.runs.append(_snapshot(context))


@then("the check exits 0")
def step_exit_zero(context):
    assert context.result.returncode == 0, (
        f"expected exit 0, got {context.result.returncode}\nstderr: {context.result.stderr}"
    )


@then("the check exits non-zero")
def step_exit_nonzero(context):
    assert context.result.returncode != 0, "expected a non-zero exit, got 0"


@then("every finding carries the keys line, severity, rule, category, message")
def step_finding_contract(context):
    fs = findings(context.result)
    assert fs, "expected at least one finding to assert the contract against"
    for f in fs:
        missing = [k for k in _TUPLE_KEYS if k not in f]
        assert not missing, f"finding {f.get('rule')!r} missing keys {missing}: {sorted(f)}"


@then("no finding carries a leverage key")
def step_no_leverage(context):
    fs = findings(context.result)
    assert fs, "expected at least one finding to assert against"
    graded = [f.get("rule") for f in fs if "leverage" in f]
    assert not graded, f"an offline run carries no grade, found it on {graded}"


@then("the last two runs report identical findings")
def step_determinism(context):
    assert len(context.runs) >= 2, "need two json runs to compare"
    a, b = context.runs[-2], context.runs[-1]
    assert a == b, f"scoring is non-deterministic across runs — {len(set(a) ^ set(b))} findings differ"


@then("the findings differ from the first run")
def step_reacts_to_edit(context):
    assert len(context.runs) >= 2, "need a baseline run and a post-edit run"
    assert context.runs[-1] != context.runs[0], "pipeline did not react to the persisted edit"


def _json_files(context) -> dict:
    return document(context.result).get("files", {})


@given('a git project whose "sub/CLAUDE.md" has findings that the project config disables')
def step_nested_file_with_project_config(context):
    context.project = build_project(context.tmpdir)
    nested = context.project / "sub"
    nested.mkdir()
    write_claude(context.project, _RICH)
    (nested / "CLAUDE.md").write_text(_SPARSE, encoding="utf-8")
    baseline = document(run_ails(context.project, "check", "sub/CLAUDE.md", "--format", "json", home=context.home))
    rules = sorted({f["rule"] for record in baseline["files"].values() for f in record.get("findings", [])})
    assert rules, "the baseline run reported no rule, so nothing was disabled"
    write_config(context.project, "disabled_rules:\n" + "".join(f"  - {rule}\n" for rule in rules))


@given('a git project "proj" elsewhere with a CLAUDE.md and a "docs/CLAUDE.md"')
def step_other_project(context):
    context.elsewhere = context.tmpdir / "elsewhere"
    proj = context.elsewhere / "proj"
    (proj / "docs").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=proj, check=True)
    (proj / "CLAUDE.md").write_text(_SPARSE, encoding="utf-8")
    (proj / "docs" / "CLAUDE.md").write_text(_SPARSE, encoding="utf-8")
    context.project = context.tmpdir / "cwd"
    context.project.mkdir()


@when('I run "ails check" on "{target}" from the folder beside it')
def step_run_elsewhere(context, target):
    absolute = str(context.elsewhere / target)
    context.result = run_ails(context.project, "check", absolute, "--format", "json", home=context.home)


@then('the json files map contains only "{name}"')
def step_json_files_only(context, name):
    assert sorted(_json_files(context)) == [name], sorted(_json_files(context))


@then("that file carries no finding")
def step_file_no_finding(context):
    assert not findings(context.result), [f["rule"] for f in findings(context.result)]


@given('a git project "proj" elsewhere with a ".claude/rules/x.md" rule file')
def step_other_project_with_rule(context):
    context.elsewhere = context.tmpdir / "elsewhere"
    proj = context.elsewhere / "proj"
    (proj / ".claude" / "rules").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=proj, check=True)
    (proj / "CLAUDE.md").write_text(_SPARSE, encoding="utf-8")
    (proj / ".claude" / "rules" / "x.md").write_text(_SPARSE, encoding="utf-8")
    context.project = context.tmpdir / "cwd"
    context.project.mkdir()


@then('the notice names "{name}" and says to run ails check in the project\'s folder')
def step_unlisted_file_notice(context, name):
    output = context.result.stdout + context.result.stderr
    file = str(context.elsewhere / name)
    assert f"{file} is not an instruction file in the project at " in output, output
    assert "run ails check in that project's folder." in output, output
