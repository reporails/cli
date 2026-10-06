"""The tier and auth-rejection vocabularies have one owner, and startup does not import the HTTP client."""

from __future__ import annotations

import subprocess
import sys

import pytest

from reporails_cli.core.platform.dto import diagnostics


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_startup_does_not_import_the_http_client() -> None:
    code = "import sys, reporails_cli.interfaces.cli.main; sys.exit(1 if 'httpx' in sys.modules else 0)"
    assert subprocess.run([sys.executable, "-c", code], check=False).returncode == 0


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_tier_labels_come_from_the_tier_sets() -> None:
    assert {"free", "pro", "team"} == diagnostics.ACCOUNT_TIERS
    assert [diagnostics.tier_label(t) for t in ("free", "pro", "team")] == ["Free", "Pro", "Team"]
    assert diagnostics.tier_label("anonymous") == diagnostics.tier_label("beta") == ""


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_auth_rejections_are_known_errors() -> None:
    assert {"invalid_api_key", "missing_or_invalid_api_key"} == diagnostics.AUTH_REJECTED_ERRORS
    assert diagnostics.AUTH_REJECTED_ERRORS <= diagnostics.KNOWN_ERRORS


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_malformed_header_is_not_read_as_a_propagation_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.core.platform.adapters.api_client import AilsClient

    monkeypatch.setattr("reporails_cli.core.platform.config.credentials.signed_in_recently", lambda key: True)
    client = AilsClient(base_url="http://srv", api_key="k")
    for token, rewritten in (("invalid_api_key", True), ("missing_or_invalid_api_key", False)):
        err = diagnostics.FunnelError(error=token, message="m")
        assert (client._early_rejection(err).message == diagnostics.STILL_REACHING_MESSAGE) is rewritten
