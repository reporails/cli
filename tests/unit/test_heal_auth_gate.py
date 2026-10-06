"""`--heal`'s write gate: a present key is not enough on its own.

`has_api_key()` only checks that a key STRING is set (env override or stored
credentials) — it never asks the server whether that key is any good. A run
that sends the key in the same invocation and gets it rejected must not then
treat the key as authenticating the write pass just because the string is
non-empty.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.dto.diagnostics import FunnelError


class TestHealAuthGate:
    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_no_key_is_not_authed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from reporails_cli.interfaces.cli.check_support import _heal_authed

        assert _heal_authed(None) is False

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_present_key_with_no_funnel_error_is_authed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from reporails_cli.interfaces.cli.check_support import _heal_authed

        monkeypatch.setenv("AILS_API_KEY", "k")
        assert _heal_authed(None) is True

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_present_key_rejected_this_run_is_not_authed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from reporails_cli.interfaces.cli.check_support import _heal_authed

        monkeypatch.setenv("AILS_API_KEY", "k")
        rejected = FunnelError(error="invalid_api_key", status=401)
        assert _heal_authed(rejected) is False

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_present_key_missing_or_invalid_is_not_authed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from reporails_cli.interfaces.cli.check_support import _heal_authed

        monkeypatch.setenv("AILS_API_KEY", "k")
        rejected = FunnelError(error="missing_or_invalid_api_key", status=401)
        assert _heal_authed(rejected) is False

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_present_key_with_unrelated_funnel_error_stays_authed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-auth funnel error (a rate limit, say) must not itself revoke the gate —
        only the two auth-rejection tokens do."""
        from reporails_cli.interfaces.cli.check_support import _heal_authed

        monkeypatch.setenv("AILS_API_KEY", "k")
        rate_limited = FunnelError(error="rate_limit_exceeded", status=429)
        assert _heal_authed(rate_limited) is True


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_still_reaching_heal_gate_prints_no_account_advice(capsys: pytest.CaptureFixture[str]) -> None:
    from types import SimpleNamespace

    from reporails_cli.core.platform.dto.diagnostics import STILL_REACHING_MESSAGE
    from reporails_cli.interfaces.cli.check_flow import _flow_heal

    err = FunnelError(error="invalid_api_key", status=401, message=STILL_REACHING_MESSAGE)
    state = SimpleNamespace(
        inputs=SimpleNamespace(heal=True),
        render=SimpleNamespace(heal_authed=False),
        pipeline=SimpleNamespace(funnel_error=err),
        targets=SimpleNamespace(output_format="text"),
    )
    _flow_heal(state)  # type: ignore[arg-type]
    out = capsys.readouterr()
    assert "needs an account" not in out.out + out.err
