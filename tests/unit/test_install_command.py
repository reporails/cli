"""Unit tests for `ails install` — the engine version pin and the per-agent
plugin commands it prints.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

import reporails_cli
from reporails_cli.interfaces.cli import install as install_module
from reporails_cli.interfaces.cli.main import app

_runner = CliRunner()

_CLAUDE_LIST_USER = "Installed plugins:\n\n  \u276f reporails@reporails\n    Version: 0.6.0\n    Scope: user\n"
_CLAUDE_LIST_BOTH = _CLAUDE_LIST_USER + "\n  \u276f reporails@reporails\n    Version: 0.6.0\n    Scope: project\n"
_CODEX_LIST = "PLUGIN  STATUS  VERSION\nreporails@reporails  installed, enabled  0.6.0\n"
_CLAUDE_MARKETS_OK = (
    "Configured marketplaces:\n\n  \u276f claude-plugins-official\n"
    "    Source: GitHub (anthropics/claude-plugins-official)\n\n"
    "  \u276f reporails\n    Source: GitHub (reporails/plugin)\n"
)
_CLAUDE_MARKETS_STALE = (
    "Configured marketplaces:\n\n  \u276f claude-plugins-official\n"
    "    Source: GitHub (anthropics/claude-plugins-official)\n\n"
    "  \u276f reporails\n    Source: Directory (/tmp/old-plugin-checkout)\n\n"
    "  \u276f other-market\n    Source: GitHub (someone/other-market)\n"
)
_CLAUDE_MARKETS_LOOKALIKE = (
    "Configured marketplaces:\n\n  \u276f other-market\n    Source: GitHub (someone/other-market)\n\n"
    "  \u276f mine\n    Source: Directory (/tmp/reporails-checkout)\n"
)
_CODEX_MARKETS_OK = "MARKETPLACE  ROOT\nreporails    /home/u/.codex/.tmp/marketplaces/reporails\n"


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
        self.kwargs: list[dict[str, Any]] = []
        self.listing = listing or {}
        self.fail = fail

    def __call__(self, cmd: list[str], **kwargs: Any) -> MagicMock:
        self.calls.append(cmd)
        self.kwargs.append(kwargs)
        result = MagicMock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        joined = " ".join(cmd[1:])
        named = f"{cmd[0].rsplit('/', 1)[-1]} {joined}"
        if joined.endswith("list"):
            result.stdout = self.listing.get(named, self.listing.get(joined, ""))
        if any(joined.startswith(f) or named.startswith(f) for f in self.fail):
            result.returncode = 1
            result.stderr = "boom"
        return result

    def commands(self) -> list[str]:
        return [" ".join([c[0].rsplit("/", 1)[-1], *c[1:]]) for c in self.calls]


def _setup(
    monkeypatch: pytest.MonkeyPatch,
    runner: _Runner,
    present: set[str],
    key: bool = False,
    tmp_path: Path | None = None,
) -> None:
    monkeypatch.setattr(install_module, "_install_to_path", lambda: True)
    monkeypatch.setattr(install_module.shutil, "which", lambda cmd: f"/bin/{cmd}" if cmd in present else None)
    monkeypatch.setattr(install_module.subprocess, "run", runner)
    monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: key)
    monkeypatch.delenv("AILS_PLUGIN_SOURCE", raising=False)
    if tmp_path is not None:
        monkeypatch.chdir(tmp_path)


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
    monkeypatch.setenv("CODEX_HOME", "/home/u/.codex")
    runner = _Runner(
        listing={
            "claude plugin marketplace list": _CLAUDE_MARKETS_OK,
            "codex plugin marketplace list": _CODEX_MARKETS_OK,
            "claude plugin list": _CLAUDE_LIST_USER,
            "codex plugin list": _CODEX_LIST,
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
    assert "/reporails:ails heal" not in out
    assert "plugin steps are printed above" in out
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
            "claude plugin marketplace list": _CLAUDE_MARKETS_OK,
            "codex plugin marketplace list": _CODEX_MARKETS_OK,
            "claude plugin list": _CLAUDE_LIST_USER,
            "codex plugin list": _CODEX_LIST,
        }
    )
    _update_setup(monkeypatch, runner, {"claude", "codex"})

    result = _runner.invoke(app, ["update"])

    assert result.exit_code == 0
    cmds = runner.commands()
    assert "claude plugin update reporails@reporails --scope user" in cmds
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
        listing={"plugin marketplace list": _CLAUDE_MARKETS_OK, "plugin list": _CLAUDE_LIST_USER},
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


def _plain(result: Any) -> str:
    return " ".join(result.stdout.split())


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_marketplace_name_match_is_exact(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`other-market` and a Source path containing "reporails" are not the `reporails` marketplace."""
    runner = _Runner(listing={"claude plugin marketplace list": _CLAUDE_MARKETS_LOOKALIKE})
    _setup(monkeypatch, runner, {"claude"}, tmp_path=tmp_path)

    _runner.invoke(app, ["install"])

    cmds = runner.commands()
    assert "claude plugin marketplace add reporails/plugin" in cmds
    assert not any("marketplace update" in c or "marketplace remove" in c for c in cmds)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_stale_marketplace_source_is_replaced(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner = _Runner(
        listing={"claude plugin marketplace list": _CLAUDE_MARKETS_STALE, "claude plugin list": _CLAUDE_LIST_USER}
    )
    _setup(monkeypatch, runner, {"claude"}, tmp_path=tmp_path)

    result = _runner.invoke(app, ["install"])

    cmds = runner.commands()
    removed = cmds.index("claude plugin marketplace remove reporails --scope user")
    added = cmds.index("claude plugin marketplace add reporails/plugin")
    assert removed < added < cmds.index("claude plugin install reporails@reporails")
    assert not any(c.startswith("claude plugin marketplace update") for c in cmds)
    assert "old source" in _plain(result)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_broken_codex_marketplace_is_removed_then_added(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner = _Runner(fail=("codex plugin marketplace list", "codex plugin list"))
    _setup(monkeypatch, runner, {"codex"}, tmp_path=tmp_path)

    _runner.invoke(app, ["install"])

    cmds = runner.commands()
    assert cmds.index("codex plugin marketplace remove reporails") < cmds.index(
        "codex plugin marketplace add reporails/plugin"
    )
    assert "codex plugin add reporails@reporails" in cmds


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_missing_agent_binary_prints_manual_command_and_skips_closing_heal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _Runner()
    _setup(monkeypatch, runner, {"codex", "uvx"}, tmp_path=tmp_path)

    result = _runner.invoke(app, ["install"])

    out = _plain(result)
    assert "Run by hand: /plugin marketplace add reporails/plugin" in out
    assert "In Claude Code, run" not in out
    assert "Claude Code's plugin steps are printed above" in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("tier", "needs_pro"),
    [("pro", False), ("free", True), ("", True)],
)
def test_closing_line_names_pro_unless_the_stored_tier_is_entitled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tier: str, needs_pro: bool
) -> None:
    runner = _Runner()
    _setup(monkeypatch, runner, {"claude"}, key=True, tmp_path=tmp_path)
    home = tmp_path / "home"
    (home / ".reporails").mkdir(parents=True)
    (home / ".reporails" / "credentials.yml").write_text(f"api_key: k\ntier: '{tier}'\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))

    result = _runner.invoke(app, ["install"])

    out = _plain(result)
    assert "/reporails:ails heal" in out
    assert ("/reporails:ails heal (Pro)" in out) is needs_pro


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_update_refreshes_every_scope_with_one_listing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runner = _Runner(
        listing={"claude plugin marketplace list": _CLAUDE_MARKETS_OK, "claude plugin list": _CLAUDE_LIST_BOTH}
    )
    _update_setup(monkeypatch, runner, {"claude"})

    _runner.invoke(app, ["update"])

    cmds = runner.commands()
    assert "claude plugin update reporails@reporails --scope user" in cmds
    assert "claude plugin update reporails@reporails --scope project" in cmds
    assert cmds.count("claude plugin list") == 1


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_project_rerun_updates_a_declared_project_marketplace(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        '{"extraKnownMarketplaces": {"reporails": {"source": {"source": "github", "repo": "reporails/plugin"}}}}',
        encoding="utf-8",
    )
    runner = _Runner(listing={"plugin list": _CLAUDE_LIST_BOTH, "plugin marketplace list": _CLAUDE_MARKETS_OK})
    _setup(monkeypatch, runner, {"claude"}, tmp_path=tmp_path)

    _runner.invoke(app, ["install", "--project"])

    cmds = runner.commands()
    assert "claude plugin marketplace update reporails" in cmds
    assert not any(c.startswith("claude plugin marketplace add") for c in cmds)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_warm_only_when_a_plugin_is_in_place_and_uv_missing_is_said(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runner = _Runner(fail=("plugin marketplace add",))
    _setup(monkeypatch, runner, {"claude", "uvx"}, tmp_path=tmp_path)
    _runner.invoke(app, ["install"])
    assert not any("uvx" in c[0] for c in runner.calls)

    runner = _Runner()
    _setup(monkeypatch, runner, {"claude"}, tmp_path=tmp_path)
    result = _runner.invoke(app, ["install"])
    assert "needs uv" in _plain(result)
    assert "https://docs.astral.sh/uv/" in _plain(result)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_agent_commands_do_not_inherit_the_agent_session(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in install_module._SESSION_ENV:
        monkeypatch.setenv(name, "1")
    runner = _Runner()
    _setup(monkeypatch, runner, {"claude", "codex"}, tmp_path=tmp_path)

    _runner.invoke(app, ["install"])

    agent_calls = [
        kw for c, kw in zip(runner.calls, runner.kwargs, strict=True) if c[0] in ("/bin/claude", "/bin/codex")
    ]
    assert agent_calls
    for kw in agent_calls:
        assert "env" in kw
        assert not set(install_module._SESSION_ENV) & set(kw["env"])


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_project_install_runs_from_the_repository_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    sub = tmp_path / "pkg" / "sub"
    sub.mkdir(parents=True)
    runner = _Runner()
    _setup(monkeypatch, runner, {"claude"}, tmp_path=sub)

    result = _runner.invoke(app, ["install", "--project"])

    claude_cwds = {kw.get("cwd") for c, kw in zip(runner.calls, runner.kwargs, strict=True) if c[0] == "/bin/claude"}
    assert claude_cwds == {tmp_path}
    assert str(tmp_path) in result.stdout.replace("\n", "")


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_user_install_does_not_count_a_project_scope_plugin_as_present(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    listing = "Installed plugins:\n\n  \u276f reporails@reporails\n    Scope: project\n"
    runner = _Runner(listing={"plugin list": listing})
    _setup(monkeypatch, runner, {"claude"}, tmp_path=tmp_path)

    _runner.invoke(app, ["install"])

    cmds = runner.commands()
    assert "claude plugin install reporails@reporails" in cmds
    assert not any(c.startswith("claude plugin update") for c in cmds)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_project_install_adds_a_declared_marketplace_the_machine_has_not_added(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        '{"extraKnownMarketplaces": {"reporails": {"source": {"source": "github", "repo": "reporails/plugin"}}}}',
        encoding="utf-8",
    )
    runner = _Runner(listing={"claude plugin marketplace list": "Configured marketplaces:\n\n  No marketplaces\n"})
    _setup(monkeypatch, runner, {"claude"}, tmp_path=tmp_path)

    _runner.invoke(app, ["install", "--project"])

    cmds = runner.commands()
    assert "claude plugin marketplace add reporails/plugin --scope project" in cmds
    assert not any(c.startswith("claude plugin marketplace update") for c in cmds)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_project_install_uses_the_nearest_git_root_in_a_nested_repository(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "backbone.yml").write_text("{}\n", encoding="utf-8")
    inner = tmp_path / "inner"
    (inner / "src").mkdir(parents=True)
    (inner / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")
    runner = _Runner()
    _setup(monkeypatch, runner, {"claude"}, tmp_path=inner / "src")

    _runner.invoke(app, ["install", "--project"])

    claude_cwds = {kw.get("cwd") for c, kw in zip(runner.calls, runner.kwargs, strict=True) if c[0] == "/bin/claude"}
    assert claude_cwds == {inner}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_codex_marketplace_on_a_local_folder_is_replaced_by_the_github_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "codex-home"
    monkeypatch.setenv("CODEX_HOME", str(home))
    listing = "MARKETPLACE  ROOT\nreporails    /tmp/old-plugin-checkout\n"
    runner = _Runner(listing={"codex plugin marketplace list": listing})
    _setup(monkeypatch, runner, {"codex"}, tmp_path=tmp_path)

    _runner.invoke(app, ["install"])

    cmds = runner.commands()
    assert cmds.index("codex plugin marketplace remove reporails") < cmds.index(
        "codex plugin marketplace add reporails/plugin"
    )


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_codex_git_marketplace_inside_the_codex_home_is_current(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "codex-home"
    monkeypatch.setenv("CODEX_HOME", str(home))
    listing = f"MARKETPLACE  ROOT\nreporails    {home}/.tmp/marketplaces/reporails\n"
    runner = _Runner(listing={"codex plugin marketplace list": listing})
    _setup(monkeypatch, runner, {"codex"}, tmp_path=tmp_path)

    _runner.invoke(app, ["install"])

    cmds = runner.commands()
    assert "codex plugin marketplace upgrade reporails" in cmds
    assert not any("marketplace remove" in c for c in cmds)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_update_says_when_it_replaces_a_stale_marketplace(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _Runner(
        listing={"claude plugin marketplace list": _CLAUDE_MARKETS_STALE, "claude plugin list": _CLAUDE_LIST_USER}
    )
    _update_setup(monkeypatch, runner, {"claude"})

    result = _runner.invoke(app, ["update"])

    assert "old source" in _plain(result)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("stored_tier", "env_key", "needs_pro"),
    [("pro", "other-key", True), ("weird", "", False), ("pro", "", False), ("free", "", True)],
)
def test_closing_line_reads_the_tier_of_the_key_in_effect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stored_tier: str, env_key: str, needs_pro: bool
) -> None:
    runner = _Runner()
    _setup(monkeypatch, runner, {"claude"}, key=True, tmp_path=tmp_path)
    home = tmp_path / "home"
    (home / ".reporails").mkdir(parents=True)
    (home / ".reporails" / "credentials.yml").write_text(f"api_key: k\ntier: '{stored_tier}'\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("AILS_API_KEY", raising=False)
    if env_key:
        monkeypatch.setenv("AILS_API_KEY", env_key)

    result = _runner.invoke(app, ["install"])

    assert ("/reporails:ails heal (Pro)" in _plain(result)) is needs_pro


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_relative_plugin_source_becomes_an_absolute_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sub = tmp_path / "repo" / "sub"
    sub.mkdir(parents=True)
    monkeypatch.chdir(sub)
    monkeypatch.setenv("AILS_PLUGIN_SOURCE", "../plugin")

    assert install_module._plugin_source() == str(tmp_path / "repo" / "plugin")
    monkeypatch.setenv("AILS_PLUGIN_SOURCE", "owner/repo")
    assert install_module._plugin_source() == "owner/repo"
