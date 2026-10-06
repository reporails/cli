"""Step definitions for the github and text formatter demonstrations.

Asserts on the rendered surface of the two `ails check` formatters the JSON
scenarios never exercise — the GitHub Actions workflow commands and the default
text scorecard — against the REAL console script's stdout (via the shared
``I run`` step in ``check_steps.py``). No in-process ``CliRunner``.
"""

from __future__ import annotations

import re

from behave import then  # type: ignore[import-untyped]

# A GitHub Actions workflow command: `::error file=F,line=N,title=T::message`.
_WORKFLOW_CMD = re.compile(r"^::(?:error|warning) file=[^,]+,line=\d+,title=.*::", re.MULTILINE)


@then("the output emits GitHub Actions workflow commands")
def step_github_commands(context):
    out = context.result.stdout
    matches = _WORKFLOW_CMD.findall(out)
    assert matches, f"no ::error/::warning workflow commands emitted:\n{out[:600]}"


@then("the text output shows the level and a finding count")
def step_text_scorecard(context):
    out = context.result.stdout
    assert "Level:" in out, f"text scorecard missing the Level line:\n{out}"
    assert re.search(r"Findings\s+[\d,]+ total", out), f"text scorecard missing the Findings total:\n{out}"
