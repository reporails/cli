"""`json_object` and `write_json_atomic`: contract and one failure path each."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.platform.utils import utils
from reporails_cli.core.platform.utils.utils import json_object, write_json_atomic


@pytest.mark.unit
def test_json_object_returns_the_object() -> None:
    assert json_object('{"a": 1}') == {"a": 1}


@pytest.mark.unit
@pytest.mark.parametrize("text", ["<html>", "[1, 2]", "", "null"])
def test_json_object_is_empty_for_non_object_bodies(text: str) -> None:
    assert json_object(text) == {}


@pytest.mark.unit
def test_write_json_atomic_writes_and_creates_parent(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "state.json"
    write_json_atomic(target, {"k": [1, 2]})
    assert json.loads(target.read_text(encoding="utf-8")) == {"k": [1, 2]}
    assert [p.name for p in target.parent.iterdir()] == ["state.json"]


@pytest.mark.unit
def test_write_json_atomic_failure_keeps_old_file_and_removes_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "state.json"
    target.write_text('{"old": true}', encoding="utf-8")

    def _boom(*_: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(utils.os, "replace", _boom)
    with pytest.raises(OSError, match="disk full"):
        write_json_atomic(target, {"new": True})
    assert json.loads(target.read_text(encoding="utf-8")) == {"old": True}
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]
