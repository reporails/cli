"""CLI/MCP parity on config surfaces: both a whole-project run and a single
config-file target must agree between `ails check` and MCP `validate`.

`_discover_files` (MCP) and `_resolve_scope_at_target` (CLI) each
built their own whole-project scope with `get_all_instruction_files`, so a
broken settings file sat outside both. This mirrors
`test_mcp_cli_equivalence.py`'s pattern with a config file in the fixture.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app
from reporails_cli.interfaces.mcp import tools

runner = CliRunner()

_has_onnx_model = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
).exists()
requires_model = pytest.mark.skipif(not _has_onnx_model, reason="Bundled ONNX model not available")


def _rules_installed() -> bool:
    from reporails_cli.core.platform.config.bootstrap import get_rules_path

    return (get_rules_path() / "core").exists()


requires_rules = pytest.mark.skipif(not _rules_installed(), reason="Rules framework not installed")


def _finding_tuples(payload: dict) -> set[tuple[str, str, int]]:
    files = payload.get("files", {})
    return {
        (finding["rule"], file_path, finding["line"])
        for file_path, entry in files.items()
        for finding in entry.get("findings", [])
    }


def _project_with_broken_hooks(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    (project).mkdir()
    (project / "CLAUDE.md").write_text(
        "# Test Project\n\nAlways run the tests before pushing.\n\nNEVER force-push to main.\n",
        encoding="utf-8",
    )
    settings = project / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps(
            {"hooks": {"PretoolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}]}},
            indent=2,
        ),
        encoding="utf-8",
    )
    return project


def _cli_payload(project: Path, *args: str) -> dict:
    cwd = os.getcwd()
    os.chdir(project)
    try:
        result = runner.invoke(app, ["check", *args, "-f", "json"])
    finally:
        os.chdir(cwd)
    assert result.exit_code in (0, 1), result.output
    return json.loads(result.output)


def _mcp_payload(project: Path) -> dict:
    return tools.validate_tool(str(project), full=True)


@requires_model
@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
def test_cli_and_mcp_agree_on_whole_project_config_findings(tmp_path: Path, monkeypatch) -> None:
    """A whole-project run with a broken settings file draws the same
    `(rule, file, line)` tuples on both surfaces, config file included."""
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.api_client.AilsClient.lint",
        lambda self, *args, **kwargs: None,
    )
    project = _project_with_broken_hooks(tmp_path)

    cli_tuples = _finding_tuples(_cli_payload(project))
    mcp_tuples = _finding_tuples(_mcp_payload(project))

    assert any(f[1].endswith("settings.json") for f in cli_tuples), (
        f"settings.json missing from the CLI whole-project run: {sorted(cli_tuples)}"
    )
    assert cli_tuples == mcp_tuples, (
        f"MCP diverges from CLI on a config-bearing project:\n"
        f"  only in mcp: {sorted(mcp_tuples - cli_tuples)}\n"
        f"  only in cli: {sorted(cli_tuples - mcp_tuples)}"
    )


@requires_model
@requires_rules
@pytest.mark.integration
@pytest.mark.subsys_server
def test_cli_and_mcp_agree_on_a_single_config_file_target(tmp_path: Path, monkeypatch) -> None:
    """A single config-file target (`ails check .claude/settings.json` / MCP
    `validate` on that same path) agrees between surfaces too."""
    monkeypatch.setattr(
        "reporails_cli.core.platform.adapters.api_client.AilsClient.lint",
        lambda self, *args, **kwargs: None,
    )
    project = _project_with_broken_hooks(tmp_path)
    settings_file = project / ".claude" / "settings.json"

    cli_tuples = _finding_tuples(_cli_payload(project, ".claude/settings.json"))
    mcp_tuples = _finding_tuples(tools.validate_tool(str(settings_file), full=True))

    assert cli_tuples, "fixture must produce at least one finding for the gate to be meaningful"
    assert cli_tuples == mcp_tuples, (
        f"MCP diverges from CLI on a single config-file target:\n"
        f"  only in mcp: {sorted(mcp_tuples - cli_tuples)}\n"
        f"  only in cli: {sorted(cli_tuples - mcp_tuples)}"
    )
