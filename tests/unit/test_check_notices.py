"""Tests for interfaces/cli/check_notices.py — the --heal user-facing notices."""

from __future__ import annotations

import pytest

from reporails_cli.interfaces.cli.check_notices import _emit_heal_auth_required


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_heal_auth_required_never_implies_a_paid_plan(capsys: pytest.CaptureFixture[str]) -> None:
    """The --heal auth-required notice must say fixes need an account —
    not that they need a paid plan. A free account is enough; the old copy
    ("the diagnosis above is free; applying fixes is not") reads as "applying
    fixes costs money", which is false and can deter the sign-up it means to
    drive."""
    _emit_heal_auth_required("text")
    output = capsys.readouterr().out
    assert "applying fixes is not" not in output.lower()
    assert "free account is enough" in output.lower()
    assert "ails auth login" in output.lower()
