"""Unit tests for `ails install` — the engine version pin and the per-agent
plugin commands it prints.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

import reporails_cli
from reporails_cli.interfaces.cli import install as install_module
from reporails_cli.interfaces.cli.main import app

_runner = CliRunner()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_to_path_pins_a_floor_not_an_exact_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """`uv tool install` gets `reporails-cli>=<version>`, never `==`.

    `uv tool upgrade` keeps an `==` pin forever, so only a floor lets a later
    `ails update` / `uv tool upgrade` move the engine past this version.
    """
    monkeypatch.setattr(install_module.shutil, "which", lambda cmd: None if cmd == "ails" else "/usr/bin/uv")

    calls: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> MagicMock:
        calls.append(cmd)
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        return result

    monkeypatch.setattr(install_module.subprocess, "run", fake_run)

    assert install_module._install_to_path() is True
    assert len(calls) == 1
    assert calls[0][:3] == ["/usr/bin/uv", "tool", "install"]
    spec = calls[0][3]
    assert spec == f"reporails-cli>={reporails_cli.__version__}"
    assert "==" not in spec


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("engine_ready", [True, False])
def test_install_prints_plugin_commands_for_every_agent(monkeypatch: pytest.MonkeyPatch, engine_ready: bool) -> None:
    """`install` prints the plugin command for every listed agent, whether or
    not the engine install succeeded, and never says the plugin is unavailable.
    """
    monkeypatch.setattr(install_module, "_install_to_path", lambda: engine_ready)

    result = _runner.invoke(app, ["install"])

    assert result.exit_code == 0
    out = " ".join(result.stdout.split())
    assert len(install_module._PLUGIN_INSTALL) == 5
    for agent, command in install_module._PLUGIN_INSTALL:
        assert agent in out
        assert " ".join(command.split()) in out
    assert "/plugin install reporails@reporails" in out
    assert "published" not in out
    assert "yet" not in out
    assert "uv on the machine" in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_help_promises_the_plugin_commands() -> None:
    """`ails install --help` says the command prints how to connect the engine to an agent."""
    result = _runner.invoke(app, ["install", "--help"])
    normalized = " ".join(result.stdout.split())  # help text wraps at panel width

    assert result.exit_code == 0
    assert "connect it to your agent" in normalized
