"""The agent registry the mapper reads skips configs it cannot use."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper import inspect as inspect_module


def _rules_dir(tmp_path: Path) -> Path:
    for name, text in (
        ("alpha", "agent: alpha\nfile_types: {}\n"),
        ("empty", ""),
        ("listy", "- not\n- a mapping\n"),
    ):
        (tmp_path / name).mkdir()
        (tmp_path / name / "config.yml").write_text(text, encoding="utf-8")
    return tmp_path


@pytest.mark.unit
@pytest.mark.subsys_map
def test_registry_skips_empty_and_non_mapping_configs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inspect_module, "get_rules_path", lambda: _rules_dir(tmp_path))
    assert inspect_module._load_registry() == {"alpha": {"agent": "alpha", "file_types": {}}}


@pytest.mark.unit
@pytest.mark.subsys_map
def test_registry_is_empty_without_a_rules_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inspect_module, "get_rules_path", lambda: tmp_path / "missing")
    assert inspect_module._load_registry() == {}
