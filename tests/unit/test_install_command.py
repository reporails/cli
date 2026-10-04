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


class _Runner:
    """Fake `subprocess.run`: records commands, answers by prefix."""

    def __init__(self, listing: dict[str, str] | None = None, fail: tuple[str, ...] = ()) -> None:
        self.calls: list[list[str]] = []
        self.listing = listing or {}
        self.fail = fail

    def __call__(self, cmd: list[str], **kwargs: Any) -> MagicMock:
        self.calls.append(cmd)
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        joined = " ".join(cmd[1:])
        if joined.endswith("list"):
            result.stdout = self.listing.get(joined, "")
        if any(joined.startswith(f) for f in self.fail):
            result.returncode = 1
            result.stderr = "boom"
        return result

    def commands(self) -> list[str]:
        return [" ".join([c[0].rsplit("/", 1)[-1], *c[1:]]) for c in self.calls]


def _setup(monkeypatch: pytest.MonkeyPatch, runner: _Runner, present: set[str], key: bool = False) -> None:
    monkeypatch.setattr(install_module, "_install_to_path", lambda: True)
    monkeypatch.setattr(install_module.shutil, "which", lambda cmd: f"/bin/{cmd}" if cmd in present else None)
    monkeypatch.setattr(install_module.subprocess, "run", runner)
    monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: key)
    monkeypatch.delenv("AILS_PLUGIN_SOURCE", raising=False)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_runs_both_agents_plugin_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner()
    _setup(monkeypatch, runner, {"claude", "codex", "uvx"})

    result = _runner.invoke(app, ["install"])

    assert result.exit_code == 0
    cmds = runner.commands()
    assert "claude plugin marketplace add reporails/plugin" in cmds
    assert "claude plugin install reporails@reporails" in cmds
    assert "codex plugin marketplace add reporails/plugin" in cmds
    assert "codex plugin add reporails@reporails" in cmds
    out = " ".join(result.stdout.split())
    for agent in ("Cursor", "GitHub Copilot", "Antigravity"):
        assert agent in out
    assert "Claude Code only" in out
    assert "ails auth login" in out
    assert "/reporails:ails heal" in out
    assert "/reload-plugins" in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_skips_absent_agents_and_signed_in_note(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner()
    _setup(monkeypatch, runner, set(), key=True)

    result = _runner_invoke()

    assert result.exit_code == 0
    assert runner.calls == []
    assert "ails auth login" not in result.stdout


def _runner_invoke() -> Any:
    return _runner.invoke(app, ["install"])


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_refreshes_what_is_already_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner(
        listing={
            "plugin marketplace list": "reporails",
            "plugin list": "reporails@reporails",
        }
    )
    _setup(monkeypatch, runner, {"claude", "codex"})

    result = _runner_invoke()

    assert result.exit_code == 0
    cmds = runner.commands()
    assert "claude plugin marketplace update reporails" in cmds
    assert "claude plugin update reporails@reporails" in cmds
    assert not any(c.startswith("claude plugin marketplace add") for c in cmds)
    assert not any(c.startswith("claude plugin install") for c in cmds)
    assert "codex plugin marketplace upgrade reporails" in cmds
    assert "codex plugin add reporails@reporails" in cmds


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_failure_prints_manual_command_and_continues(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner(fail=("plugin marketplace add",))
    _setup(monkeypatch, runner, {"claude", "codex"})

    result = _runner_invoke()

    assert result.exit_code == 0
    out = " ".join(result.stdout.split())
    assert "Run by hand: /plugin marketplace add reporails/plugin" in out
    assert "Run by hand: codex plugin marketplace add" in out
    assert "/reporails:ails heal" in out
    assert not any(c.startswith("claude plugin install") for c in runner.commands())


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_timeout_and_oserror_do_not_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    outcomes = iter([subprocess.TimeoutExpired("x", 120), OSError("nope")])

    def boom(cmd: list[str], **kwargs: Any) -> MagicMock:
        raise next(outcomes, OSError("nope"))

    _setup(monkeypatch, _Runner(), {"claude", "uvx"})
    monkeypatch.setattr(install_module.subprocess, "run", boom)

    result = _runner_invoke()

    assert result.exit_code == 0
    assert "Run by hand" in result.stdout


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_plugin_source_override(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner()
    _setup(monkeypatch, runner, {"claude", "codex"})
    monkeypatch.setenv("AILS_PLUGIN_SOURCE", "/tmp/local-plugin")

    _runner_invoke()

    cmds = runner.commands()
    assert "claude plugin marketplace add /tmp/local-plugin" in cmds
    assert "codex plugin marketplace add /tmp/local-plugin" in cmds


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("version", "spec"),
    [
        ("0.6.0", "reporails-cli>=0.6.0,<0.7"),
        ("0.6.3", "reporails-cli>=0.6.0,<0.7"),
        ("0.7.1", "reporails-cli>=0.7.0,<0.8"),
        ("1.2.0", "reporails-cli>=1.2.0,<1.3"),
    ],
)
def test_warm_step_uses_the_plugin_pin(monkeypatch: pytest.MonkeyPatch, version: str, spec: str) -> None:
    runner = _Runner()
    _setup(monkeypatch, runner, {"uvx"})
    monkeypatch.setattr(reporails_cli, "__version__", version)

    install_module._warm_engine()

    assert runner.calls == [["/bin/uvx", "--from", spec, "ails", "--version"]]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_help_promises_the_plugin_commands() -> None:
    """`ails install --help` says the command prints how to connect the engine to an agent."""
    result = _runner.invoke(app, ["install", "--help"])
    normalized = " ".join(result.stdout.split())  # help text wraps at panel width

    assert result.exit_code == 0
    assert "add the plugin to Claude Code and Codex" in normalized


_CLAUDE_LIST_USER = "Installed plugins:\n\n  \u276f reporails@reporails\n    Version: 0.6.0\n    Scope: user\n"
_CODEX_LIST = "PLUGIN  STATUS  VERSION\nreporails@reporails  installed, enabled  0.6.0\n"


def _update_setup(monkeypatch: pytest.MonkeyPatch, runner: _Runner, present: set[str]) -> None:
    import reporails_cli.interfaces.cli.commands as commands_module

    monkeypatch.setattr(commands_module, "_update_engine", lambda: True)
    monkeypatch.setattr(install_module.shutil, "which", lambda cmd: f"/bin/{cmd}" if cmd in present else None)
    monkeypatch.setattr(install_module.subprocess, "run", runner)
    monkeypatch.delenv("AILS_PLUGIN_SOURCE", raising=False)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_update_refreshes_agents_that_have_the_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner(
        listing={
            "plugin marketplace list": "reporails",
            "plugin list": _CLAUDE_LIST_USER + _CODEX_LIST,
        }
    )
    _update_setup(monkeypatch, runner, {"claude", "codex"})

    result = _runner.invoke(app, ["update"])

    assert result.exit_code == 0
    cmds = runner.commands()
    assert "claude plugin update reporails@reporails" in cmds
    assert "codex plugin add reporails@reporails" in cmds
    assert not any(c.startswith("claude plugin install") for c in cmds)
    assert "Claude Code plugin refreshed" in result.stdout
    assert "Codex plugin refreshed" in result.stdout


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_update_skips_absent_agents_and_reports_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner(listing={"plugin list": "Installed plugins:\n\n  No plugins installed\n"})
    _update_setup(monkeypatch, runner, {"claude"})

    result = _runner.invoke(app, ["update"])

    assert result.exit_code == 0
    assert not any("codex" in c for c in runner.commands())
    assert not any(" install " in f" {c} " or " update " in f" {c} " for c in runner.commands())
    out = " ".join(result.stdout.split())
    assert "Claude Code: plugin not installed" in out
    assert "ails install" in out
    assert "Codex" not in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_update_refresh_failure_prints_manual_command(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner(
        listing={"plugin marketplace list": "reporails", "plugin list": _CLAUDE_LIST_USER},
        fail=("plugin update",),
    )
    _update_setup(monkeypatch, runner, {"claude"})

    result = _runner.invoke(app, ["update"])

    assert result.exit_code == 0
    assert "Run by hand" in result.stdout


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_project_scopes_claude_commands_and_notes_codex(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner()
    _setup(monkeypatch, runner, {"claude", "codex"})

    result = _runner.invoke(app, ["install", "--project"])

    assert result.exit_code == 0
    cmds = runner.commands()
    assert "claude plugin marketplace add reporails/plugin --scope project" in cmds
    assert "claude plugin install reporails@reporails --scope project" in cmds
    assert "codex plugin add reporails@reporails" in cmds
    assert not any(c.startswith("codex") and "--scope" in c for c in cmds)
    out = " ".join(result.stdout.split())
    assert "Codex installs the plugin for your user" in out
    assert "for this project" in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_project_rerun_updates_at_project_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    listing = "Installed plugins:\n\n  \u276f reporails@reporails\n    Scope: project\n"
    runner = _Runner(listing={"plugin list": listing})
    _setup(monkeypatch, runner, {"claude"})

    result = _runner.invoke(app, ["install", "--project"])

    assert result.exit_code == 0
    cmds = runner.commands()
    assert "claude plugin update reporails@reporails --scope project" in cmds
    assert not any(c.startswith("claude plugin install") for c in cmds)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_install_project_installs_when_only_user_scope_has_the_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner(listing={"plugin list": _CLAUDE_LIST_USER})
    _setup(monkeypatch, runner, {"claude"})

    _runner.invoke(app, ["install", "--project"])

    assert "claude plugin install reporails@reporails --scope project" in runner.commands()
