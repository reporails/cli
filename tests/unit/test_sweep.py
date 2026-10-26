"""The shared sweep: units dropped by age, total size or count, oldest first."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.cache import sweep as sweep_module
from reporails_cli.core.cache.sweep import sweep

NOW = 1_000_000.0
DAY = 86400.0


def _file(folder: Path, name: str, age_s: float, size: int = 1) -> Path:
    path = folder / name
    path.write_bytes(b"x" * size)
    os.utime(path, (NOW - age_s, NOW - age_s))
    return path


def _names(folder: Path) -> set[str]:
    return {p.name for p in folder.iterdir()}


@pytest.mark.unit
@pytest.mark.subsys_caching
@pytest.mark.parametrize(
    ("age", "kept"),
    [(10 * DAY - 1, True), (10 * DAY, True), (10 * DAY + 1, False)],
    ids=["younger", "exactly-at-limit", "older"],
)
def test_age_limit_boundary(tmp_path: Path, age: float, kept: bool) -> None:
    _file(tmp_path, "a", age)
    sweep(tmp_path.iterdir(), now=NOW, max_age_s=10 * DAY)
    assert (_names(tmp_path) == {"a"}) is kept


@pytest.mark.unit
@pytest.mark.subsys_caching
@pytest.mark.parametrize(
    ("limit", "left"),
    [(50, {"a", "b", "c"}), (49, {"b", "c"}), (30, {"b", "c"}), (29, {"c"}), (9, set())],
)
def test_size_boundary(tmp_path: Path, limit: int, left: set[str]) -> None:
    _file(tmp_path, "a", 300, 20)
    _file(tmp_path, "b", 200, 20)
    _file(tmp_path, "c", 100, 10)
    sweep(tmp_path.iterdir(), max_bytes=limit)
    assert _names(tmp_path) == left


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_count_limit_keeps_newest(tmp_path: Path) -> None:
    for i, name in enumerate("abcd"):
        _file(tmp_path, name, 400 - i * 100)
    sweep(tmp_path.iterdir(), max_units=2)
    assert _names(tmp_path) == {"c", "d"}


@pytest.mark.unit
@pytest.mark.subsys_caching
@pytest.mark.parametrize(
    ("newest_age", "left"),
    [(5 * DAY, {"s1.old", "s1.new", "s2.x"}), (11 * DAY, {"s2.x"})],
    ids=["newest-file-keeps-the-unit", "whole-unit-aged-out"],
)
def test_unit_is_deleted_whole_by_newest_file(tmp_path: Path, newest_age: float, left: set[str]) -> None:
    _file(tmp_path, "s1.old", 50 * DAY)
    _file(tmp_path, "s1.new", newest_age)
    _file(tmp_path, "s2.x", 1 * DAY)
    sweep(tmp_path.iterdir(), unit_of=lambda p: p.name.split(".")[0], now=NOW, max_age_s=10 * DAY)
    assert _names(tmp_path) == left


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_unit_size_counts_every_file(tmp_path: Path) -> None:
    _file(tmp_path, "s1.a", 300, 10)
    _file(tmp_path, "s1.b", 290, 10)
    _file(tmp_path, "s2.a", 100, 10)
    sweep(tmp_path.iterdir(), unit_of=lambda p: p.name.split(".")[0], max_bytes=15)
    assert _names(tmp_path) == {"s2.a"}


@pytest.mark.unit
@pytest.mark.subsys_caching
@pytest.mark.parametrize("vanishes", ["at-stat", "at-unlink"])
def test_file_vanishing_mid_sweep_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, vanishes: str) -> None:
    gone = _file(tmp_path, "gone", 300)
    _file(tmp_path, "old", 200)
    _file(tmp_path, "new", 100)
    listing = list(tmp_path.iterdir())
    if vanishes == "at-stat":
        gone.unlink()
    else:
        real = sweep_module._delete

        def racing(unit: sweep_module._Unit) -> None:
            gone.unlink(missing_ok=True)  # another sweeper got there first
            real(unit)

        monkeypatch.setattr(sweep_module, "_delete", racing)
    sweep(listing, max_units=1)
    assert _names(tmp_path) == {"new"}
