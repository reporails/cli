"""npm / npx installs: detection, `ails update` hint and one-shot npx copies."""

from __future__ import annotations

import subprocess

import pytest

from reporails_cli.core.install.self_update import InstallMethod, detect_install_method
from reporails_cli.interfaces.cli import commands as commands_module
from reporails_cli.interfaces.cli.install import _is_temporary_ails

pytestmark = [pytest.mark.unit, pytest.mark.subsys_cli_ux]


@pytest.mark.parametrize(
    ("launcher", "expected"),
    [("npm", InstallMethod.NPM), ("npx", InstallMethod.NPX)],
)
def test_launcher_selects_install_method(monkeypatch, launcher, expected):
    monkeypatch.setenv("AILS_LAUNCHER", launcher)
    assert detect_install_method() == expected


@pytest.mark.parametrize("launcher", ["", "pip", "NPM", "yarn", "uv"])
def test_other_launcher_values_fall_through(monkeypatch, launcher):
    monkeypatch.setenv("AILS_LAUNCHER", launcher)
    assert detect_install_method() not in (InstallMethod.NPM, InstallMethod.NPX)


@pytest.mark.parametrize(
    ("launcher", "expected_text"),
    [
        ("npm", "npm install -g @reporails/cli@latest"),
        ("npx", "A bare `npx @reporails/cli` runs the latest release on every run"),
    ],
)
def test_update_prints_hint_and_runs_nothing(monkeypatch, capsys, launcher, expected_text):
    monkeypatch.setenv("AILS_LAUNCHER", launcher)
    calls: list[object] = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a))
    assert commands_module._update_engine() is True
    assert expected_text in " ".join(capsys.readouterr().out.split())
    assert calls == []


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/home/u/.npm/_npx/ab12cd/node_modules/.bin/ails", True),
        ("/usr/local/bin/ails", False),
    ],
)
def test_npx_copy_is_temporary(path, expected):
    assert _is_temporary_ails(path, None) is expected
