"""`--offline` holds for its own run only: later runs and a daemon forked by it stay online."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.mapper import daemon
from reporails_cli.core.platform.config.bootstrap import offline_requested, run_offline


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_offline_flag_does_not_outlive_the_check_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.interfaces.cli import check_flow
    from reporails_cli.interfaces.cli.main import app

    monkeypatch.delenv("AILS_OFFLINE", raising=False)
    during: list[bool] = []
    monkeypatch.setattr(check_flow, "run_check_flow", lambda _state: during.append(offline_requested()))
    CliRunner().invoke(app, ["check", str(tmp_path), "--offline"])
    assert during == [True]
    assert "AILS_OFFLINE" not in os.environ


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_preset_offline_value_is_put_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_OFFLINE", "yes")
    with run_offline(True):
        assert os.environ["AILS_OFFLINE"] == "1"
    assert os.environ["AILS_OFFLINE"] == "yes"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_daemon_forked_during_an_offline_run_is_not_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AILS_OFFLINE", raising=False)
    seen: list[str | None] = []
    monkeypatch.setattr(daemon, "is_daemon_running", lambda: False)
    monkeypatch.setattr(daemon.os, "fork", lambda: 0)
    monkeypatch.setattr(daemon, "_become_daemon", lambda _t, _f: seen.append(os.environ.get("AILS_OFFLINE")))
    monkeypatch.setattr(daemon, "socket_path", lambda: Path(os.devnull + ".none"))
    with run_offline(True):
        daemon._fork_daemon(None, None)  # type: ignore[arg-type]
    assert seen == [None]
