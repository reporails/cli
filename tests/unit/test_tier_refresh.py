"""The stored tier follows the tier a diagnostics reply names (for the stored key only)."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from typing import Any, ClassVar
from unittest.mock import patch

import httpx
import pytest
import yaml

from reporails_cli.core.platform.adapters.api_client import DEFAULT_SERVER_URL, AilsClient
from reporails_cli.core.platform.config.credentials import effective_tier
from reporails_cli.core.platform.dto.diagnostics import FunnelError
from tests.unit.test_api_client import _make_map, _payload_with_file

_ROOT = Path("/tmp/reporails-test-scan-root")


def _seed(home: Path, tier: str, key: str = "rr_stored") -> Path:
    path = home / ".reporails" / "credentials.yml"
    path.parent.mkdir(parents=True)
    path.write_text(yaml.dump({"api_key": key, "account": "octocat", "tier": tier}), encoding="utf-8")
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


def _lint(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    reply: Any,
    env_key: str | None = None,
    base_url: str = DEFAULT_SERVER_URL,
    dev_mode: bool = False,
) -> Any:
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # Path.home() reads USERPROFILE on Windows
    if dev_mode:
        monkeypatch.setenv("AILS_DEV_MODE", "1")
    else:
        monkeypatch.delenv("AILS_DEV_MODE", raising=False)
    if env_key:
        monkeypatch.setenv("AILS_API_KEY", env_key)
    else:
        monkeypatch.delenv("AILS_API_KEY", raising=False)
    with (
        patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=_payload_with_file()),
        patch("httpx.post", return_value=reply),
    ):
        return AilsClient(base_url=base_url).lint(_make_map(), root=_ROOT)


def _stored(path: Path) -> dict[str, str]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.unit
@pytest.mark.subsys_api
def test_free_to_pro_refreshes_stored_tier_and_status(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _seed(tmp_path, "free")
    _lint(monkeypatch, tmp_path, _Ok("pro"))
    assert _stored(path) == {"api_key": "rr_stored", "account": "octocat", "tier": "pro"}
    if sys.platform != "win32":  # POSIX mode bits are not enforced on Windows
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert effective_tier() == "pro"


@pytest.mark.unit
@pytest.mark.subsys_api
def test_pro_to_free_refreshes_stored_tier(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _seed(tmp_path, "pro")
    _lint(monkeypatch, tmp_path, _Ok("free"))
    assert _stored(path)["tier"] == "free"
    assert effective_tier() == "free"


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


@pytest.mark.unit
@pytest.mark.subsys_api
def test_non_default_server_leaves_file_alone(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _seed(tmp_path, "free")
    before = path.read_text(encoding="utf-8")
    _lint(monkeypatch, tmp_path, _Ok("pro"), base_url="http://localhost:8001")
    assert path.read_text(encoding="utf-8") == before


@pytest.mark.unit
@pytest.mark.subsys_api
def test_dev_mode_leaves_file_alone(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _seed(tmp_path, "free")
    before = path.read_text(encoding="utf-8")
    _lint(monkeypatch, tmp_path, _Ok("pro"), dev_mode=True)
    assert path.read_text(encoding="utf-8") == before


@pytest.mark.unit
@pytest.mark.subsys_api
def test_refresh_replaces_the_file_in_one_step(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import os

    path = _seed(tmp_path, "free")
    replaced: list[tuple[str, str]] = []
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (replaced.append((str(a), str(b))), real(a, b))[1])
    _lint(monkeypatch, tmp_path, _Ok("pro"))
    assert [dst for _, dst in replaced] == [str(path)]
    assert _stored(path)["tier"] == "pro"
    if sys.platform != "win32":  # POSIX mode bits are not enforced on Windows
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in path.parent.iterdir()] == ["credentials.yml"]


@pytest.mark.unit
@pytest.mark.subsys_api
def test_refresh_never_overwrites_a_concurrent_sign_in(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from reporails_cli.core.platform.config import credentials as owner

    path = _seed(tmp_path, "free")
    real = owner.yaml.safe_load
    calls = {"n": 0}

    def _login_lands_between_reads(text: str) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:  # the re-read just before the replace
            return {"api_key": "rr_new", "account": "other", "tier": "free"}
        return real(text)

    monkeypatch.setattr(owner.yaml, "safe_load", _login_lands_between_reads)
    owner.refresh_stored_tier("rr_stored", "pro", path)
    assert _stored(path)["tier"] == "free"
    assert [p.name for p in path.parent.iterdir()] == ["credentials.yml"]
