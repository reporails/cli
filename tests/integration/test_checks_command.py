"""Integration coverage for `ails rules list` (with repeatable `--capability`)."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.platform.config.bootstrap import get_rules_path
from reporails_cli.interfaces.cli.main import app

_runner = CliRunner()

requires_rules = pytest.mark.skipif(
    not (get_rules_path() / "core").exists(),
    reason="Rules framework not installed",
)


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _run(*args: str) -> tuple[int, str, str]:
    # Force a wide, color-free render so help/option tokens (e.g. `--capability`)
    # are not split by ANSI styling or column wrapping — CI runners set FORCE_COLOR
    # and a narrow terminal width, which broke literal substring assertions.
    env = {**os.environ, "COLUMNS": "200", "NO_COLOR": "1"}
    proc = subprocess.run(["ails", *args], capture_output=True, text=True, check=False, env=env)
    return proc.returncode, _ANSI_RE.sub("", proc.stdout), _ANSI_RE.sub("", proc.stderr)


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_rules_list_help() -> None:
    code, out, _ = _run("rules", "list", "--help")
    assert code == 0
    assert "--capability" in out
    assert "--agent" in out
    assert "--severity" in out


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_rules_list_capability_skill_text() -> None:
    code, out, _ = _run("rules", "list", "--capability=skill", "--agent=claude", "-f", "text")
    assert code == 0
    assert "# Structure" in out
    assert "CORE:S:0024" in out


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_rules_list_capability_skill_json() -> None:
    code, out, _ = _run("rules", "list", "--capability=skill", "--agent=claude", "-f", "json")
    assert code == 0
    payload = json.loads(out)
    assert payload["capability"] == "skill"
    assert payload["capabilities"] == ["skill"]
    assert payload["agent"] == "claude"
    assert payload["count"] > 0
    for entry in payload["checks"]:
        for key in ("id", "title", "category", "severity", "type"):
            assert key in entry


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_rules_list_capability_md_includes_examples() -> None:
    code, out, _ = _run("rules", "list", "--capability=skill", "--agent=claude", "-f", "md")
    assert code == 0
    assert out.startswith("# Checks for authoring a skill")
    assert "**Pass**:" in out


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_rules_list_capability_md_no_examples() -> None:
    code, out, _ = _run("rules", "list", "--capability=skill", "--agent=claude", "-f", "md", "--no-examples")
    assert code == 0
    assert "**Pass**:" not in out
    assert "**Fail**:" not in out


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_rules_list_repeatable_capability() -> None:
    """Multiple `--capability` flags union the filter."""
    code, out, _ = _run("rules", "list", "--capability=skill", "--capability=agent", "--agent=claude", "-f", "json")
    assert code == 0
    payload = json.loads(out)
    assert set(payload["capabilities"]) == {"skill", "agent"}
    # Should yield more rules than skill-only
    code_one, out_one, _ = _run("rules", "list", "--capability=skill", "--agent=claude", "-f", "json")
    assert code_one == 0
    assert payload["count"] >= json.loads(out_one)["count"]


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_rules_list_severity_filter() -> None:
    code, out, _ = _run("rules", "list", "--agent=claude", "--severity=high", "-f", "json")
    assert code == 0
    payload = json.loads(out)
    for entry in payload["checks"]:
        assert entry["severity"] in ("critical", "high")


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_rules_list_invalid_severity() -> None:
    code, _, _err = _run("rules", "list", "--severity=bogus")
    assert code != 0


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_rules_agents_lists_known() -> None:
    code, out, _ = _run("rules", "agents", "-f", "json")
    assert code == 0
    payload = json.loads(out)
    assert "agents" in payload
    assert "claude" in payload["agents"]


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_rules_capabilities_for_claude() -> None:
    code, out, _ = _run("rules", "capabilities", "--agent=claude", "-f", "json")
    assert code == 0
    payload = json.loads(out)
    assert payload["agent"] == "claude"
    assert "skills" in payload["capabilities"]
    assert "main" in payload["capabilities"]


@pytest.mark.integration
@pytest.mark.subsys_lint
@requires_rules
def test_targeted_check_skips_project_shape_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A targeted (file-scoped) run must not fire CORE:S:0010; a whole-project scan still does."""
    proj = tmp_path / "single"
    proj.mkdir()
    (proj / "AGENTS.md").write_text("# Solo\n\nThe only instruction file.\n")
    monkeypatch.chdir(proj)

    whole = _runner.invoke(app, ["check", "-f", "json"])
    assert whole.exit_code == 0
    assert "CORE:S:0010" in whole.output  # whole-project scan enforces the ≥2-file shape

    targeted = _runner.invoke(app, ["check", "AGENTS.md", "-f", "json"])
    assert targeted.exit_code == 0
    assert "CORE:S:0010" not in targeted.output  # narrowed subset must not misfire


@pytest.mark.integration
@pytest.mark.subsys_lint
def test_explain_accepts_slug() -> None:
    """Top-level `ails explain` resolves slug → ID."""
    code_id, out_id, _ = _run("explain", "CORE:S:0002")
    code_slug, out_slug, _ = _run("explain", "section-headers-present")
    assert code_id == 0
    assert code_slug == 0
    assert out_id == out_slug
