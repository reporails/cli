"""Tests for interfaces/cli/check_notices.py — the --heal user-facing notices."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.dto.diagnostics import FunnelError
from reporails_cli.interfaces.cli.check_notices import _emit_heal_withheld

_KEY = "reporails_cli.core.platform.adapters.api_client.has_api_key"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_heal_auth_required_says_fixes_need_a_pro_account(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The --heal notice says fixes need a Pro account and points to `ails login`."""
    monkeypatch.setattr(_KEY, lambda: False)
    _emit_heal_withheld("text", funnel_error=None, tier=None, server_replied=False)
    output = capsys.readouterr().out
    assert "pro account" in output.lower()
    assert "ails login" in output.lower()
    assert "enable" not in output.lower()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_heal_notice_for_a_signed_in_run_without_a_server_reply_does_not_say_pro(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_KEY, lambda: True)
    _emit_heal_withheld("text", funnel_error=None, tier="free", server_replied=False)
    assert "pro account" not in capsys.readouterr().out.lower()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_heal_notice_for_a_rejected_key_points_at_sign_in(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_KEY, lambda: True)
    _emit_heal_withheld(
        "text", funnel_error=FunnelError(error="invalid_api_key", status=401), tier=None, server_replied=False
    )
    assert "ails login" in capsys.readouterr().out.lower()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_heal_notice_under_json_goes_to_stderr_with_its_code(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_KEY, lambda: True)
    _emit_heal_withheld("json", funnel_error=None, tier="free", server_replied=True)
    captured = capsys.readouterr()
    assert captured.out == "" and '"heal_requires_pro"' in captured.err
