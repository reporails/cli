"""The credentials owner: reading, the tier in effect, clearing and the recent sign-in check."""

from __future__ import annotations

import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reporails_cli.core.platform.config import credentials
from reporails_cli.core.platform.config.credentials import write_credentials_file
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


# --- write_credentials_file: permissions and atomic replace (moved from the retired auth command tests) ---


def _record() -> dict[str, str]:
    return {"api_key": "KEY", "account": "octocat", "tier": "free"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_write_creates_nested_dirs_and_block_style_yaml(tmp_path: Path) -> None:
    path = tmp_path / "a" / "b" / ".reporails" / "credentials.yml"
    assert write_credentials_file(path, _record()) is True
    text = path.read_text(encoding="utf-8")
    assert "api_key: KEY" in text
    assert "{" not in text
    assert write_credentials_file(path, _record()) is True  # an existing directory is fine


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits not enforced on Windows")
def test_write_is_owner_only_from_the_first_byte(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / ".reporails" / "credentials.yml"
    modes: list[int] = []
    real_open = os.open

    def _spy(target: object, flags: int, mode: int = 0o777) -> int:
        modes.append(mode)
        return real_open(target, flags, mode)

    monkeypatch.setattr(os, "open", _spy)
    write_credentials_file(path, _record())
    assert modes == [0o600]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits not enforced on Windows")
def test_write_narrows_an_existing_wider_file(tmp_path: Path) -> None:
    path = tmp_path / ".reporails" / "credentials.yml"
    path.parent.mkdir(parents=True)
    path.write_text("api_key: OLD\n", encoding="utf-8")
    path.chmod(0o644)
    write_credentials_file(path, {**_record(), "api_key": "NEWKEY"})
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "NEWKEY" in path.read_text(encoding="utf-8")
    assert [p.name for p in path.parent.iterdir()] == ["credentials.yml"]
