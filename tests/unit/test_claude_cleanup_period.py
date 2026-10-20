"""Claude Code's `cleanupPeriodDays` setting, read from the settings files the module already reads."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.platform.config import claude_settings
from reporails_cli.core.platform.config.claude_settings import claude_cleanup_period_days


@pytest.fixture(autouse=True)
def _no_managed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    real = claude_settings._settings_patterns

    def patterns() -> dict[str, list[str]]:
        scopes = real()
        scopes["managed"] = [str(tmp_path / "managed" / "managed-settings.json")]
        scopes["managed_dropin"] = [str(tmp_path / "managed" / "d" / "*.json")]
        return scopes

    monkeypatch.setattr(claude_settings, "_settings_patterns", patterns)


def _set(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"cleanupPeriodDays": value}), encoding="utf-8")


def _user() -> Path:
    return Path.home() / ".claude" / "settings.json"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_unset_reads_as_none(tmp_path: Path) -> None:
    assert claude_cleanup_period_days(tmp_path / "proj") is None


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_set_reads_the_days(tmp_path: Path) -> None:
    _set(_user(), 7)
    assert claude_cleanup_period_days(tmp_path / "proj") == 7


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize("bad", [0, -3, True, False, 2.5, "7", None, [7]])
def test_invalid_value_reads_as_none(tmp_path: Path, bad: object) -> None:
    _set(_user(), bad)
    assert claude_cleanup_period_days(tmp_path / "proj") is None


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_invalid_project_value_does_not_hide_the_user_one(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    _set(_user(), 9)
    _set(root / ".claude" / "settings.json", 0)
    assert claude_cleanup_period_days(root) == 9


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("scopes", "expected"),
    [
        (("user", "project"), 20),
        (("user", "project", "local"), 30),
        (("user", "project", "local", "managed"), 40),
        (("user", "managed"), 40),
    ],
)
def test_precedence_later_scope_wins(tmp_path: Path, scopes: tuple[str, ...], expected: int) -> None:
    root = tmp_path / "proj"
    paths = {
        "user": (_user(), 10),
        "project": (root / ".claude" / "settings.json", 20),
        "local": (root / ".claude" / "settings.local.json", 30),
        "managed": (tmp_path / "managed" / "managed-settings.json", 40),
    }
    for scope in scopes:
        path, days = paths[scope]
        _set(path, days)
    assert claude_cleanup_period_days(root) == expected
