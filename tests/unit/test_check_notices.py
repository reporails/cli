"""Tests for interfaces/cli/check_notices.py — the --heal user-facing notices."""

from __future__ import annotations

import pytest

from reporails_cli.interfaces.cli.check_notices import _emit_heal_auth_required


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_heal_auth_required_says_fixes_need_a_pro_account(capsys: pytest.CaptureFixture[str]) -> None:
    """The --heal notice says fixes need a Pro account and points to `ails login`."""
    _emit_heal_auth_required("text")
    output = capsys.readouterr().out
    assert "pro account" in output.lower()
    assert "ails login" in output.lower()
