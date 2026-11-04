"""A file Claude Code or the OS writes (a scope declaring `maintainer: system`) is never checked, yet stays listed
for a session's loads."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agent_discovery import discover_from_config

pytestmark = [pytest.mark.unit, pytest.mark.subsys_classify]


@pytest.fixture
def user_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    folder = tmp_path / ".claude"
    folder.mkdir()
    (folder / "settings.json").write_text('{"permissions": {}}', encoding="utf-8")
    (folder / "remote-settings.json").write_text('{"permissions": {}}', encoding="utf-8")
    return folder


def _names(found: tuple[list[Path], list[Path], list[Path]] | None) -> set[str]:
    assert found is not None
    return {p.name for bucket in found for p in bucket}


def test_check_leaves_out_the_remote_settings_cache(user_folder: Path) -> None:
    found = discover_from_config(user_folder, "claude", repo_scoped=True)
    assert _names(found) == {"settings.json"}


def test_session_loads_still_list_the_remote_settings_cache(user_folder: Path) -> None:
    found = discover_from_config(user_folder, "claude", repo_scoped=False)
    assert {"settings.json", "remote-settings.json"} <= _names(found)
