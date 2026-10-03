"""The client package holds no module that grades a finding."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[2] / "src"
_GONE_MODULES = (
    "reporails_cli.core.platform.policy.leverage",
    "reporails_cli.core.platform.policy.completeness",
)
_GONE_NAMES = (
    "LEVERAGE_TABLE",
    "_CEILING_BOUND",
    "LIKELY_FLOOR_POINTS",
    "UNLIKELY_CEIL_POINTS",
    "tier_for_points",
    "structural_class_points",
    "counts_toward_gap",
    "ATOM_LEVEL_LOCAL_RULES",
    "leverage_basis",
    "stamp_structural_tiers",
)


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
@pytest.mark.parametrize("module", _GONE_MODULES)
def test_the_grading_modules_are_not_importable(module: str) -> None:
    assert importlib.util.find_spec(module) is None


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_no_source_file_names_a_grading_table_or_formula() -> None:
    hits = [
        f"{path.relative_to(_SRC)}: {name}"
        for path in _SRC.rglob("*.py")
        for text in (path.read_text(encoding="utf-8", errors="ignore"),)
        for name in _GONE_NAMES
        if name in text
    ]
    assert hits == []
