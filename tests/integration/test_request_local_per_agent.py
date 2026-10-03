"""A run that auto-detects several agents sends every agent's findings, like each agent's own run.

The local findings the diagnostics request carries are resolved under the agents whose rules
ran, so a finding under an agent's own rule is sent exactly as it is on
that agent's explicit run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

_BROKEN_HOOK = '{"hooks":{"PretoolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/abs/a.sh"}]}]}}'


def _claude_and_cursor_project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    (project / ".cursor" / "rules").mkdir(parents=True)
    (project / "CLAUDE.md").write_text(
        "# Project\n\n## Commands\n\n- Run `make test` before committing.\n- Never commit secrets.\n",
        encoding="utf-8",
    )
    (project / "AGENTS.md").write_text("# Project\n\n- Run `make lint` before pushing.\n", encoding="utf-8")
    (project / ".claude" / "settings.json").write_text(_BROKEN_HOOK, encoding="utf-8")
    (project / ".cursor" / "rules" / "style.mdc").write_text(
        '---\ndescription: style\nglobs: "**/*.py"\n---\n\n- Use `ruff format` on every Python file.\n',
        encoding="utf-8",
    )
    return project


def _check(project: Path, monkeypatch: pytest.MonkeyPatch, *extra: str) -> tuple[list[Any], int, set[str]]:
    """Run `ails check`, returning the request's local entries, its structural total and the reported rules."""
    from reporails_cli.core.platform.adapters.api_client import AilsClient

    sent: dict[str, Any] = {}

    def _capture(self: Any, ruleset_map: Any, local: Any, structural_required: int, **_kw: Any) -> None:
        sent["local"], sent["required"] = list(local), structural_required

    monkeypatch.setattr(AilsClient, "lint", _capture)
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", ".", *extra, "--format", "json"])
    assert result.exit_code in (0, 1), result.output
    files = json.loads(result.output)["files"]
    reported = {f["rule"] for v in files.values() for f in (v["findings"] if isinstance(v, dict) else v)}
    return sent["local"], sent["required"], reported


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_auto_detected_run_sends_each_agents_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _claude_and_cursor_project(tmp_path)
    auto, _, reported = _check(project, monkeypatch)
    sent = {e.rule for e in auto}
    assert {"CLAUDE:S:0005", "CLAUDE:G:0001", "CURSOR:S:0001"} <= reported
    assert {"CLAUDE:S:0005", "CLAUDE:G:0001", "CURSOR:S:0001"} <= sent


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_auto_detected_run_sends_what_the_agents_own_run_sends(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _claude_and_cursor_project(tmp_path)
    auto, _, _ = _check(project, monkeypatch)
    explicit, _, _ = _check(project, monkeypatch, "--agent", "claude")
    key = lambda e: (e.rule, e.file, e.line, e.severity)  # noqa: E731
    own = {key(e) for e in explicit if e.rule.startswith("CLAUDE:")}
    assert own
    assert own <= {key(e) for e in auto}


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_auto_detected_run_counts_the_structural_rules_it_is_checked_against(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reporails_cli.core.platform.adapters.registry import structural_rule_ids

    project = _claude_and_cursor_project(tmp_path)
    _, required, _ = _check(project, monkeypatch)
    ran = structural_rule_ids("claude") | structural_rule_ids("cursor")
    assert required == len(ran)


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_explicit_agent_run_sends_what_the_agents_registry_defines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reporails_cli.core.platform.adapters.registry import registry_rule_ids, structural_rule_ids

    project = _claude_and_cursor_project(tmp_path)
    explicit, required, reported = _check(project, monkeypatch, "--agent", "claude")
    expected = {r for r in reported if r in registry_rule_ids("claude")}
    assert {e.rule for e in explicit} == expected
    assert required == len(structural_rule_ids("claude"))
