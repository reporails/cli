"""The credentials owner: reading, the tier in effect, clearing and the recent sign-in check."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reporails_cli.core.platform.config import credentials
from reporails_cli.core.platform.contract.errors import CredentialsUnreadableError

NOW = datetime(2026, 5, 10, 12, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AILS_API_KEY", raising=False)
    return tmp_path


def _store(home: Path, text: str) -> None:
    path = home / ".reporails" / "credentials.yml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_read_credentials_returns_the_stored_record(home: Path) -> None:
    _store(home, "api_key: rr_k\ntier: pro\n")
    assert credentials.read_credentials() == {"api_key": "rr_k", "tier": "pro"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("content", [None, "api_key: [unclosed", "- a\n- b\n", ""])
def test_read_credentials_is_lenient_and_the_strict_loader_keeps_its_fault(home: Path, content: str | None) -> None:
    if content is not None:
        _store(home, content)
    assert credentials.read_credentials() == {}
    if content == "api_key: [unclosed":
        with pytest.raises(CredentialsUnreadableError):
            credentials.load_credentials_record()
    else:
        assert credentials.load_credentials_record() == {}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_env_api_key_reads_the_override(monkeypatch: pytest.MonkeyPatch) -> None:
    assert credentials.env_api_key() == ""
    monkeypatch.setenv("AILS_API_KEY", "rr_env")
    assert credentials.env_api_key() == "rr_env"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("env", "expected"),
    [(None, "pro"), ("rr_k", "pro"), ("rr_other", "")],
    ids=["stored-key", "env-same-key", "env-other-key"],
)
def test_effective_tier_follows_the_key_in_effect(
    home: Path, monkeypatch: pytest.MonkeyPatch, env: str | None, expected: str
) -> None:
    _store(home, "api_key: rr_k\ntier: pro\n")
    if env:
        monkeypatch.setenv("AILS_API_KEY", env)
    assert credentials.effective_tier() == expected


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_clear_credentials_removes_the_file_and_tolerates_none(home: Path) -> None:
    credentials.clear_credentials()
    _store(home, "api_key: rr_k\n")
    credentials.clear_credentials()
    assert not credentials.credentials_path().exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("stamp", "key", "expected"),
    [
        ((NOW - timedelta(seconds=30)).isoformat(), "rr_k", True),
        ((NOW - timedelta(seconds=30)).isoformat().replace("+00:00", "Z"), "rr_k", True),
        ((NOW - timedelta(seconds=30)).replace(tzinfo=None).isoformat(), "rr_k", True),
        ((NOW - timedelta(seconds=600)).isoformat(), "rr_k", False),
        ((NOW + timedelta(seconds=600)).isoformat(), "rr_k", False),
        ((NOW - timedelta(seconds=30)).isoformat(), "rr_other", False),
        ((NOW - timedelta(seconds=30)).isoformat(), "", False),
        ("garbage", "rr_k", False),
        (None, "rr_k", False),
    ],
    ids=["fresh", "fresh-z", "fresh-naive", "stale", "future", "other-key", "empty-key", "garbage", "absent"],
)
def test_signed_in_recently(home: Path, stamp: str | None, key: str, expected: bool) -> None:
    suffix = f"signed_in_at: '{stamp}'\n" if stamp is not None else ""
    _store(home, f"api_key: rr_k\n{suffix}")
    assert credentials.signed_in_recently(key, now=NOW) is expected


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_signed_in_recently_with_no_file_or_a_corrupt_one(home: Path) -> None:
    assert credentials.signed_in_recently("rr_k", now=NOW) is False
    _store(home, "api_key: [unclosed")
    assert credentials.signed_in_recently("rr_k", now=NOW) is False


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_signed_in_recently_honours_within_s(home: Path) -> None:
    _store(home, f"api_key: rr_k\nsigned_in_at: '{(NOW - timedelta(seconds=300)).isoformat()}'\n")
    assert credentials.signed_in_recently("rr_k", now=NOW) is False
    assert credentials.signed_in_recently("rr_k", within_s=600, now=NOW) is True
