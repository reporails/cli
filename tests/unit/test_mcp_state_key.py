"""The validate circuit-breaker key: one path under two project folders keeps two states."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.interfaces.mcp.validate_state import state_key

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]


def test_one_path_under_two_roots_keeps_two_states(tmp_path: Path) -> None:
    file = tmp_path / "CLAUDE.md"
    first, second = tmp_path / "a", tmp_path / "b"
    assert state_key(str(file), first, ()) != state_key(str(file), second, ())
    assert state_key(str(file), first, ()) == state_key(str(file), first, ())


def test_targets_still_split_the_state(tmp_path: Path) -> None:
    assert state_key(str(tmp_path), tmp_path, ()) != state_key(str(tmp_path), tmp_path, ("skills",))
