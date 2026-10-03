"""Mutation-closing behavioral tests for interfaces/cli/config_command.py.

Covers the no-args help behaviour, the empty-config `or {}` fallback, the
`mkdir(parents=, exist_ok=)` arguments on both save paths, and the
`yaml.safe_dump` formatting arguments (block style + sorted keys).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.config_command import (
    _load_config,
    _save_config,
    _save_global_config,
    config_app,
)

runner = CliRunner()

_GLOBAL_PATH = "reporails_cli.interfaces.cli.config_command._global_config_path"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_no_args_shows_help_not_error() -> None:
    """Invoking `config` with no subcommand shows the commands help, not a 'Missing command'
    error — kills `no_args_is_help` True -> False (which prints the error form instead)."""
    result = runner.invoke(config_app, [])
    assert "Missing command" not in result.output
    assert "Commands" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_load_config_empty_file_returns_empty_dict(tmp_path: Path) -> None:
    """An empty config file yields {} (safe_load -> None -> `or {}`) — kills `or` -> `and`,
    which would return None and break every caller."""
    ails = tmp_path / ".ails"
    ails.mkdir()
    (ails / "config.yml").write_text("", encoding="utf-8")
    assert _load_config(tmp_path) == {}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_set_creates_nested_project_dirs(tmp_path: Path) -> None:
    """Writing into a not-yet-existing nested project root creates intermediates
    (kills `mkdir(parents=True)` -> `False`, which would FileNotFoundError)."""
    deep = tmp_path / "a" / "b" / "c"
    result = runner.invoke(config_app, ["set", "default_agent", "claude", "--path", str(deep)])
    assert result.exit_code == 0
    assert (deep / ".ails" / "config.yml").exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_set_into_existing_ails_dir_succeeds(tmp_path: Path) -> None:
    """When `.ails/` already exists, the write still succeeds — kills `exist_ok=True` -> `False`,
    which would FileExistsError."""
    (tmp_path / ".ails").mkdir()
    result = runner.invoke(config_app, ["set", "default_agent", "claude", "--path", str(tmp_path)])
    assert result.exit_code == 0


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_global_set_creates_nested_dirs_and_tolerates_existing(tmp_path: Path) -> None:
    """Global save creates missing parents and tolerates a pre-existing dir — kills the
    `parents=True`/`exist_ok=True` -> `False` mutations on the global save path."""
    target = tmp_path / "x" / "y" / ".reporails" / "config.yml"
    with patch(_GLOBAL_PATH, return_value=target):
        first = runner.invoke(config_app, ["set", "--global", "default_agent", "claude"])
        assert first.exit_code == 0
        assert target.exists()
        # Second write hits an already-existing parent dir (exercises exist_ok=True).
        second = runner.invoke(config_app, ["set", "--global", "default_agent", "cursor"])
        assert second.exit_code == 0


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_get_without_global_reads_project_config(tmp_path: Path) -> None:
    """`config get` without `--global` reads the PROJECT config — kills the `--global` default
    False -> True (which would read the empty global config and report '(not set)')."""
    _save_config(tmp_path, {"default_agent": "claude"})
    empty_global = tmp_path / ".reporails" / "config.yml"
    with patch(_GLOBAL_PATH, return_value=empty_global):
        result = runner.invoke(config_app, ["get", "default_agent", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "claude" in result.output
    assert "not set" not in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_save_config_uses_block_style(tmp_path: Path) -> None:
    """List values serialise in block style (`- item`), not flow style — kills
    `default_flow_style=False` -> `True`."""
    _save_config(tmp_path, {"exclude_dirs": ["vendor", "node_modules"]})
    text = (tmp_path / ".ails" / "config.yml").read_text(encoding="utf-8")
    assert "- vendor" in text
    assert "[vendor" not in text


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_save_config_sorts_keys(tmp_path: Path) -> None:
    """Keys serialise in sorted order regardless of insertion order — kills
    `sort_keys=True` -> `False`."""
    _save_config(tmp_path, {"tier": "beta", "default_agent": "claude"})
    text = (tmp_path / ".ails" / "config.yml").read_text(encoding="utf-8")
    assert text.index("default_agent:") < text.index("tier:")


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_save_global_config_block_style_and_sorted(tmp_path: Path) -> None:
    """The global save path also serialises block-style and sorted — kills the
    `default_flow_style=False` -> `True` and `sort_keys=True` -> `False` mutations on L113."""
    target = tmp_path / ".reporails" / "config.yml"
    with patch(_GLOBAL_PATH, return_value=target):
        _save_global_config({"tier": "beta", "default_agent": "claude"})
    text = target.read_text(encoding="utf-8")
    assert text.index("default_agent:") < text.index("tier:")
    assert "{" not in text
