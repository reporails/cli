"""Shared fixtures for unit tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def make_config_file(tmp_path: Path):
    """Factory: write YAML to a temp config file."""

    def _make(content: str, subdir: str = ".reporails", name: str = "config.yml") -> Path:
        d = tmp_path / subdir
        d.mkdir(parents=True, exist_ok=True)
        p = d / name
        p.write_text(content)
        return p

    return _make
