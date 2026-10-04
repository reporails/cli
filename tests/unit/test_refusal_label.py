"""A run the server refused is not an offline run: banner names the tier, Quality says why."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.dto.diagnostics import FunnelError
from reporails_cli.core.platform.runtime.merger import CombinedResult, FindingItem
from reporails_cli.formatters.text import display


def _render(err: FunnelError | None, tmp_path, capsys) -> str:
    finding = FindingItem(file=str(tmp_path / "CLAUDE.md"), line=2, severity="warning", rule="CORE:S:0001", message="m")
    result = CombinedResult(findings=(finding,), quality=None, server_error=err)
    display.print_text_result(
        result, elapsed_ms=0, ascii_mode=True, verbose=False, funnel_error=err, project_root=tmp_path
    )
    return capsys.readouterr().out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_rate_limit_refusal_shows_free_banner_and_reason(tmp_path, capsys) -> None:
    err = FunnelError(error="rate_limit_exceeded", tier="free", limit=5, reset_in=3600, status=429)
    out = _render(err, tmp_path, capsys)
    assert "offline" not in out
    assert "Diagnostics\n" in out
    assert "n/a (hourly limit reached)" in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_too_large_refusal_shows_reason(tmp_path, capsys) -> None:
    err = FunnelError(error="payload_too_large", tier="free", limit=100, size=200, status=413)
    out = _render(err, tmp_path, capsys)
    assert "offline" not in out
    assert "n/a (project over the size cap)" in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_paid_tier_refusal_shows_pro_banner(tmp_path, capsys) -> None:
    err = FunnelError(error="payload_too_large", tier="pro", limit=100, size=200, status=413)
    assert "Diagnostics — Pro" in _render(err, tmp_path, capsys)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("err", [None, FunnelError(error="timeout", reset_in=5), FunnelError(error="network_error")])
def test_unreachable_server_stays_offline(err, tmp_path, capsys) -> None:
    out = _render(err, tmp_path, capsys)
    assert "Diagnostics — offline" in out
    assert "n/a (server diagnostics unavailable)" in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_local_preflight_refusal_does_not_claim_pro(tmp_path, capsys) -> None:
    # Preflight presumes "pro" for a keyed caller; no server named it, so it must not set the banner.
    err = FunnelError(error="atom_cap_exceeded", tier="pro", limit=100, size=200, status=None)
    out = _render(err, tmp_path, capsys)
    assert "Diagnostics — Pro" not in out
    assert "n/a (project over the size cap)" in out
