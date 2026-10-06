"""Mutation-closing test for `core/lint/regex/__init__.py::get_checks_paths`."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.regex import get_checks_paths
from reporails_cli.core.platform.dto.models import (
    Category,
    Rule,
    RuleType,
    Severity,
)


def _rule(rule_id: str, yml_path: Path | None) -> Rule:
    return Rule(
        id=rule_id,
        title=rule_id,
        slug=rule_id.lower().replace(":", "-"),
        category=Category.STRUCTURE,
        type=RuleType.MECHANICAL,
        severity=Severity.HIGH,
        yml_path=yml_path,
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_get_checks_paths_excludes_nonexistent_yml(tmp_path: Path) -> None:
    """Only checks.yml paths that actually exist on disk are returned.

    Kills the `is not None and exists() -> or` mutant: with `or`, a rule whose
    yml_path is set but missing from disk would leak into the result.
    """
    present = tmp_path / "present.yml"
    present.write_text("checks: []\n", encoding="utf-8")
    missing = tmp_path / "missing.yml"  # never created

    rules = {
        "A": _rule("CORE:S:0001", present),
        "B": _rule("CORE:S:0002", missing),
    }
    assert get_checks_paths(rules) == [present]
