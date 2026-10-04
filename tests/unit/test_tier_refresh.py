"""The stored tier follows the tier a diagnostics reply names (for the stored key only)."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import patch

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from reporails_cli.core.platform.adapters.api_client import AilsClient
from reporails_cli.core.platform.dto.diagnostics import FunnelError
from reporails_cli.interfaces.cli.auth_command import auth_app
from tests.unit.test_api_client import _make_map, _payload_with_file

runner = CliRunner()
_ROOT = Path("/tmp/reporails-test-scan-root")


def _seed(home: Path, tier: str, key: str = "rr_stored") -> Path:
    path = home / ".reporails" / "credentials.yml"
    path.parent.mkdir(parents=True)
    path.write_text(yaml.dump({"api_key": key, "github_login": "octocat", "tier": tier}), encoding="utf-8")
    path.chmod(0o600)
    return path


class _Ok:
    status_code = 200

    def __init__(self, tier: str) -> None:
        self._tier = tier

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {"tier": self._tier, "report": {}}


class _Refused:
    status_code = 429
    headers: ClassVar[dict[str, str]] = {}

    def __init__(self, tier: str) -> None:
        self.text = json.dumps({"error": "rate_limited", "tier": tier, "reset_in": 60})

    def raise_for_status(self) -> None:
        raise httpx.HTTPStatusError("429", request=None, response=self)  # type: ignore[arg-type]


def _lint(monkeypatch: pytest.MonkeyPatch, home: Path, reply: Any, env_key: str | None = None) -> Any:
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("AILS_DEV_MODE", raising=False)
    if env_key:
        monkeypatch.setenv("AILS_API_KEY", env_key)
    else:
        monkeypatch.delenv("AILS_API_KEY", raising=False)
    with (
        patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=_payload_with_file()),
        patch("httpx.post", return_value=reply),
    ):
        return AilsClient(base_url="https://example.test").lint(_make_map(), root=_ROOT)


def _stored(path: Path) -> dict[str, str]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.unit
@pytest.mark.subsys_api
def test_free_to_pro_refreshes_stored_tier_and_status(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _seed(tmp_path, "free")
    _lint(monkeypatch, tmp_path, _Ok("pro"))
    assert _stored(path) == {"api_key": "rr_stored", "github_login": "octocat", "tier": "pro"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    out = runner.invoke(auth_app, ["status"]).output
    assert "Tier: pro" in out
    assert "as of your last check or sign-in" in out


@pytest.mark.unit
@pytest.mark.subsys_api
def test_pro_to_free_refreshes_stored_tier(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _seed(tmp_path, "pro")
    _lint(monkeypatch, tmp_path, _Ok("free"))
    assert _stored(path)["tier"] == "free"
    assert "Tier: free" in runner.invoke(auth_app, ["status"]).output


@pytest.mark.unit
@pytest.mark.subsys_api
def test_server_refusal_naming_a_tier_refreshes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _seed(tmp_path, "pro")
    response = _lint(monkeypatch, tmp_path, _Refused("free"))
    assert response.funnel_error is not None
    assert _stored(path)["tier"] == "free"


@pytest.mark.unit
@pytest.mark.subsys_api
def test_env_key_for_a_different_principal_leaves_file_alone(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _seed(tmp_path, "free")
    before = path.read_text(encoding="utf-8")
    _lint(monkeypatch, tmp_path, _Ok("pro"), env_key="rr_other")
    assert path.read_text(encoding="utf-8") == before


@pytest.mark.unit
@pytest.mark.subsys_api
def test_local_preflight_refusal_leaves_file_alone(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _seed(tmp_path, "free")
    before = path.read_text(encoding="utf-8")
    refusal = FunnelError(error="payload_too_large", tier="pro")
    with patch("reporails_cli.core.platform.adapters.api_client.preflight_oversized", return_value=refusal):
        response = _lint(monkeypatch, tmp_path, _Ok("pro"))
    assert response.funnel_error is refusal
    assert path.read_text(encoding="utf-8") == before


@pytest.mark.unit
@pytest.mark.subsys_api
def test_unwritable_credentials_never_break_a_check(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _seed(tmp_path, "free")
    with patch(
        "reporails_cli.core.platform.config.credentials.write_credentials_file", side_effect=OSError("read-only")
    ):
        response = _lint(monkeypatch, tmp_path, _Ok("pro"))
    assert response.result is not None
    assert response.result.tier == "pro"
