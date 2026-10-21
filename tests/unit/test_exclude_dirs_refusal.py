"""A folder value the run cannot read is refused where it comes from, naming the flag or the setting."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.platform.config import config as config_mod
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.contract.errors import ConfigUnreadableError
from reporails_cli.interfaces.cli.completion import complete_capability, complete_target_token
from reporails_cli.interfaces.cli.config_command import config_app
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()
_REFUSED = ["docs/*", "**/docs", "docs\\x", "../x", "a?b"]
_ACCEPTED = ["[slug]", "app/[id]", "./docs", "/docs", "docs/."]


@pytest.fixture
def global_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A global config location under tmp, used by the reader and by `ails config`."""
    path = tmp_path / "home" / "config.yml"
    path.parent.mkdir()
    monkeypatch.setattr(config_mod, "get_global_config_path", lambda: path)
    monkeypatch.setattr("reporails_cli.interfaces.cli.config_command.get_global_config_path", lambda: path)
    return path


def _project(tmp_path: Path, name: str | None = None, value: str = "docs/*") -> Path:
    root = tmp_path / "proj"
    (root / ".ails").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# Project\n\nUse uv.\n", encoding="utf-8")
    if name:
        (root / ".ails" / name).write_text(f"exclude_dirs: ['{value}']\n", encoding="utf-8")
    return root


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("name", ["config.yml", "config.local.yml"])
@pytest.mark.parametrize("value", _REFUSED)
def test_project_file_refuses_a_bad_folder_value(tmp_path: Path, global_path: Path, name: str, value: str) -> None:
    root = _project(tmp_path, name, value)
    with pytest.raises(ConfigUnreadableError) as raised:
        get_project_config(root)
    message = str(raised.value)
    assert str(root / ".ails" / name) in message
    assert "exclude_dirs" in message and value in message and "exclude_files" in message


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_global_file_refuses_a_bad_folder_value(tmp_path: Path, global_path: Path) -> None:
    global_path.write_text("exclude_dirs: ['docs/*']\n", encoding="utf-8")
    with pytest.raises(ConfigUnreadableError) as raised:
        get_project_config(_project(tmp_path))
    message = str(raised.value)
    assert str(global_path) in message and "exclude_dirs" in message and "docs/*" in message
    assert "exclude_files" in message


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("value", _ACCEPTED)
def test_project_file_accepts_a_folder_value(tmp_path: Path, global_path: Path, value: str) -> None:
    root = _project(tmp_path, "config.yml", value)
    assert value in get_project_config(root).exclude_dirs


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("use_global", [False, True])
def test_config_set_refuses_a_bad_folder_value_and_leaves_the_file(
    tmp_path: Path, global_path: Path, use_global: bool
) -> None:
    root = _project(tmp_path, "config.yml", "docs")
    target = global_path if use_global else root / ".ails" / "config.yml"
    if use_global:
        global_path.write_text("default_agent: claude\n", encoding="utf-8")
    before = target.read_bytes()
    args = ["config", "set", "exclude_dirs", "ok,[x]*", "--path", str(root)] + (["--global"] if use_global else [])
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "Error: exclude_dirs: '[x]*' is not a folder name or a folder path" in result.output
    assert str(target) not in result.output
    assert "exclude_files" in result.output
    assert target.read_bytes() == before


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_config_set_writes_bracketed_folder_values(tmp_path: Path, global_path: Path) -> None:
    root = _project(tmp_path)
    result = runner.invoke(config_app, ["set", "exclude_dirs", "docs,[slug]", "--path", str(root)])
    assert result.exit_code == 0
    assert get_project_config(root).exclude_dirs == ["docs", "[slug]"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_check_refuses_a_bad_exclude_dirs_flag(tmp_path: Path, global_path: Path) -> None:
    root = _project(tmp_path)
    result = runner.invoke(app, ["check", str(root), "--exclude-dirs", "docs/*"])
    assert result.exit_code == 2
    assert "--exclude-dirs" in result.output and "docs/*" in result.output and "--exclude-files" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_check_shows_brackets_in_the_refusal_literally(tmp_path: Path, global_path: Path) -> None:
    result = runner.invoke(app, ["check", str(_project(tmp_path)), "--exclude-dirs", "[x]*"])
    assert result.exit_code == 2
    assert "'[x]*'" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_check_does_not_refuse_a_bracketed_exclude_dirs_flag(tmp_path: Path, global_path: Path) -> None:
    result = runner.invoke(app, ["check", str(_project(tmp_path)), "--exclude-dirs", "[slug]"])
    assert "Invalid value" not in result.output


@pytest.mark.unit
@pytest.mark.subsys_server
def test_mcp_validate_and_heal_apply_name_the_refused_setting(tmp_path: Path, global_path: Path) -> None:
    from reporails_cli.interfaces.mcp.server import _run_heal_apply, _run_validate

    root = _project(tmp_path, "config.yml")
    payload = asyncio.run(_run_validate(str(root), True, None))
    assert payload["error"] == "config_unreadable"
    message = str(payload["message"])
    assert "exclude_dirs" in message and "docs/*" in message
    healed = asyncio.run(_run_heal_apply(str(root)))
    assert healed.startswith("heal_apply: ") and "exclude_dirs" in healed


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_completion_offers_nothing_for_a_refused_config(
    tmp_path: Path, global_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(_project(tmp_path, "config.yml"))
    assert complete_capability("") == []
    assert complete_target_token("") == []


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_shape_error_in_a_later_setting_is_reported_before_a_refused_folder_value(
    tmp_path: Path, global_path: Path
) -> None:
    root = _project(tmp_path)
    (root / ".ails" / "config.yml").write_text("exclude_dirs: ['docs/*']\nexclude_files: [1]\n", encoding="utf-8")
    with pytest.raises(ConfigUnreadableError) as raised:
        get_project_config(root)
    assert "exclude_files" in str(raised.value)
    assert "exclude_dirs" not in str(raised.value)
