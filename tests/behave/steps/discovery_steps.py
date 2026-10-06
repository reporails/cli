"""Step definitions for the discovery / classification / level demonstrations.

Builds a real git project on disk and drives the REAL ``ails check`` console
script via subprocess (through ``features/support.py``) — the composed front of
the pipeline: filesystem walk, instruction-file discovery, surface
classification, and the ordinal level walk. No in-process ``CliRunner``.
"""

from __future__ import annotations

from behave import given, then, when  # type: ignore[import-untyped]
from support import build_project, document, write_claude  # behave puts features/ on sys.path

# Sparse-but-valid instruction bodies for each surface. Content is deliberately
# thin — these scenarios guard discovery/classification/level, not scoring, so
# the bodies only need to make each file a real instruction surface on disk.
_MAIN = "# Rules\n\n- Always run tests before commit.\n"
_RULES = "# Workflow\n\n- Open a pull request for every change.\n"
_AGENT = "# Reviewer\n\n- Review diffs for correctness before approving.\n"


def _write(project, relpath: str, content: str) -> None:
    """Write ``content`` to ``project/relpath``, creating parent dirs."""
    target = project / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _level_rank(level: str) -> int:
    """Ordinal rank of a level string (``"L0"`` -> 0, ``"L3"`` -> 3)."""
    return int(level.lstrip("Ll") or "0")


@given("a git project with a CLAUDE.md, a rules file, and an agent file")
def step_multi_surface_project(context):
    context.project = build_project(context.tmpdir)
    write_claude(context.project, _MAIN)
    _write(context.project, ".claude/rules/workflow.md", _RULES)
    _write(context.project, ".claude/agents/reviewer.md", _AGENT)


@given("a git project with a lone CLAUDE.md")
def step_lone_claude(context):
    context.project = build_project(context.tmpdir)
    context.levels = []
    write_claude(context.project, _MAIN)


@given("a git project with no instruction files")
def step_empty_project(context):
    context.project = build_project(context.tmpdir)


@when("I add a rules surface and an agent surface")
def step_broaden_surfaces(context):
    _write(context.project, ".claude/rules/workflow.md", _RULES)
    _write(context.project, ".claude/agents/reviewer.md", _AGENT)


@when("I record the json level")
def step_record_level(context):
    if getattr(context, "levels", None) is None:
        context.levels = []
    context.levels.append(document(context.result)["level"])


@then("the json files map contains CLAUDE.md, the rules file, and the agent file")
def step_files_map_complete(context):
    # The `files` map is findings-by-file: it is empty whenever nothing in the
    # thin fixture bodies trips a finding, which happens offline with no
    # server. Assert on `surface_health[].file_count` instead — discovery and
    # classification populate it independent of whether anything was found,
    # so this stays a real discovery guard with no server dependency.
    surfaces = {s["name"]: s["file_count"] for s in document(context.result).get("surface_health", [])}
    expected = {"Main": 1, "Rules": 1, "Agents": 1}
    short = {name: (surfaces.get(name, 0), n) for name, n in expected.items() if surfaces.get(name, 0) < n}
    assert not short, (
        f"discovery dropped a surface file; surface_health file_count = {surfaces}, expected >= {expected}"
    )


@then("the json surfaces classify them as Main, Rules, and Agents")
def step_surfaces_classified(context):
    names = {s["name"] for s in document(context.result).get("surface_health", [])}
    expected = {"Main", "Rules", "Agents"}
    missing = expected - names
    assert not missing, f"classification missing surfaces {sorted(missing)}; got {sorted(names)}"


@then("each recorded level ranks at or above the previous")
def step_levels_monotonic(context):
    ranks = [_level_rank(lvl) for lvl in context.levels]
    assert ranks == sorted(ranks), f"level regressed as surfaces broadened: {context.levels}"


@then("the last recorded level ranks above the first")
def step_last_above_first(context):
    assert len(context.levels) >= 2, "need a baseline level and a post-broadening level"
    assert _level_rank(context.levels[-1]) > _level_rank(context.levels[0]), (
        f"broadening surfaces did not raise the level: {context.levels}"
    )


@then("the output reports no instruction files")
def step_reports_empty(context):
    out = context.result.stdout + context.result.stderr
    assert "no instruction files" in out.lower(), f"expected a no-instruction-files message; got:\n{out}"


@then("neither stream contains a Python traceback")
def step_no_traceback(context):
    combined = context.result.stdout + context.result.stderr
    assert "Traceback (most recent call last)" not in combined, f"crash traceback in output:\n{combined}"
