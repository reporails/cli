"""A plain whole-project `ails check` reaches config surfaces (hooks, permissions,
MCP servers, plugin manifests), not only instruction files.

Before the fix, the default scan built its scope from `get_all_instruction_files`
alone, which never returns an agent's `config_files` — so a broken settings file
sat in the project untouched by a bare `ails check`, and only surfaced once a
user knew to target it directly (`ails check hooks`, `ails check <path>`). A
single explicit config-file target had its own, separate gap: given as an
absolute path from a cwd outside the project, with no ancestor `.git` or IDE
marker directory to anchor on, project-root resolution landed one level too low
(the file's own parent directory) and detected no agent there at all, so the
file was accepted as a target but checked against nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

MAIN_FILE = "# Test Project\n\nAlways run the tests before pushing.\n\nNEVER force-push to main.\n"

# A hook event name Claude Code does not recognize.
BROKEN_HOOKS = json.dumps(
    {"hooks": {"PretoolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}]}},
    indent=2,
)


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    (project).mkdir(parents=True)
    (project / "CLAUDE.md").write_text(MAIN_FILE, encoding="utf-8")
    settings = project / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(BROKEN_HOOKS, encoding="utf-8")
    return project


def _findings_by_file(monkeypatch: pytest.MonkeyPatch, cwd: Path, *args: str) -> dict[str, set[str]]:
    monkeypatch.chdir(cwd)
    result = runner.invoke(app, ["check", *args, "-f", "json"])
    data = json.loads(result.output[result.output.index("{") :])
    return {path: {f["rule"] for f in record["findings"]} for path, record in data.get("files", {}).items()}


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_whole_project_run_reaches_the_settings_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A bare `ails check .` (no target, no capability) lists the broken settings
    file with its hook-event finding — the file a plain scan must reach on its own."""
    project = _project(tmp_path)
    by_file = _findings_by_file(monkeypatch, project, ".")

    settings_entries = [rules for path, rules in by_file.items() if path.endswith("settings.json")]
    assert settings_entries, f"settings.json missing from a whole-project run: {sorted(by_file)}"
    assert "CLAUDE:S:0005" in settings_entries[0]


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_whole_project_run_with_no_target_token_also_reaches_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same, for the even-more-bare `ails check` with no target argument at all."""
    project = _project(tmp_path)
    by_file = _findings_by_file(monkeypatch, project)

    settings_entries = [rules for path, rules in by_file.items() if path.endswith("settings.json")]
    assert settings_entries, f"settings.json missing from a whole-project run: {sorted(by_file)}"
    assert "CLAUDE:S:0005" in settings_entries[0]


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_absolute_config_file_target_from_another_cwd_is_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`ails check <absolute path to .claude/settings.json>`, run from a cwd outside
    the project and with no `.git` (or other marker) to anchor root resolution on,
    still finds and checks the file — it must not resolve to an empty scope."""
    project = _project(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    settings_abs = str((project / ".claude" / "settings.json").resolve())

    by_file = _findings_by_file(monkeypatch, elsewhere, settings_abs)

    assert by_file, "absolute config-file target resolved to an empty scope"
    rules = next(iter(by_file.values()))
    assert "CLAUDE:S:0005" in rules
