"""Mutation-closing behavioral tests for interfaces/cli/auth_command.py.

Covers the no-args help behaviour, `_write_credentials` filesystem + permission
handling, the device-flow poll loop's pending/slow_down handling, the exchange
response's waitlist branch, the hidden `--platform-url` option, and the base-URL
override precedence.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import httpx
import pytest
import typer
from typer.testing import CliRunner

import reporails_cli.interfaces.cli.auth_command as auth
from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from reporails_cli.interfaces.cli.auth_command import (
    _handle_exchange_response,
    _poll_github_token,
    _write_credentials,
    auth_app,
)

runner = CliRunner()


class _FakePost:
    """Returns queued dict payloads on successive `.json()` calls."""

    def __init__(self, payloads: list[dict[str, str]]) -> None:
        self._payloads = list(payloads)

    def __call__(self, *args: object, **kwargs: object) -> _FakePost:
        self._current = self._payloads.pop(0)
        return self

    def json(self) -> dict[str, str]:
        return self._current


# --- no-args help ----------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_auth_no_args_shows_help_not_error() -> None:
    """A bare `auth` invocation shows the commands help, not a 'Missing command' error —
    kills `no_args_is_help` True -> False."""
    result = runner.invoke(auth_app, [])
    assert "Missing command" not in result.output
    assert "Commands" in result.output


# --- _write_credentials ----------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_write_credentials_creates_nested_dir_block_style(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Writing into a not-yet-existing nested dir creates intermediates (kills `parents=True`
    -> `False`) and serialises block-style YAML (kills `default_flow_style=False` -> `True`)."""
    creds = tmp_path / "a" / "b" / ".reporails" / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds)
    _write_credentials("KEY", "octocat", "beta")
    assert creds.exists()
    text = creds.read_text(encoding="utf-8")
    assert "api_key: KEY" in text
    assert "{" not in text


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_write_credentials_tolerates_existing_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A pre-existing parent dir does not break the write — kills `exist_ok=True` -> `False`."""
    parent = tmp_path / ".reporails"
    parent.mkdir()
    creds = parent / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds)
    _write_credentials("KEY", "octocat", "beta")
    assert creds.exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits not enforced on Windows")
def test_write_credentials_restricts_permissions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """On POSIX the credentials file ends at 0o600 — kills `== "win32"` -> `!=`, which would
    take the Windows branch and skip the owner-only open."""
    creds = tmp_path / ".reporails" / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds)
    _write_credentials("KEY", "octocat", "beta")
    assert stat.S_IMODE(creds.stat().st_mode) == 0o600


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits not enforced on Windows")
def test_write_credentials_file_is_owner_only_from_its_first_byte(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The file must never exist at a wider mode, even briefly — spy on the
    `os.open` call itself (not the mode after the fact) to prove the file is
    created at 0o600 directly, instead of written at a default mode and
    narrowed by a later `chmod` (which leaves a race window on a shared host)."""
    creds = tmp_path / ".reporails" / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds)
    recorded_modes: list[int] = []
    real_open = os.open

    def _spy_open(path: object, flags: int, mode: int = 0o777) -> int:
        recorded_modes.append(mode)
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", _spy_open)
    _write_credentials("KEY", "octocat", "free")
    assert recorded_modes == [0o600]
    assert stat.S_IMODE(creds.stat().st_mode) == 0o600


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits not enforced on Windows")
def test_write_credentials_directory_is_owner_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`~/.reporails` is 0o700, not the umask-widened `mkdir` default."""
    creds = tmp_path / ".reporails" / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds)
    _write_credentials("KEY", "octocat", "free")
    assert stat.S_IMODE(creds.parent.stat().st_mode) == 0o700


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits not enforced on Windows")
def test_write_credentials_narrows_an_existing_wider_mode_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`os.open`'s mode argument applies only at file creation — an existing
    `credentials.yml` left at 0o644 (an older CLI version, a restore that
    dropped permissions) must still end at 0o600 after a new key is written,
    not keep its wider mode."""
    creds = tmp_path / ".reporails" / "credentials.yml"
    creds.parent.mkdir(parents=True)
    creds.write_text("api_key: OLD\n", encoding="utf-8")
    creds.chmod(0o644)
    monkeypatch.setattr(auth, "credentials_path", lambda: creds)

    _write_credentials("NEWKEY", "octocat", "free")

    assert stat.S_IMODE(creds.stat().st_mode) == 0o600
    assert "NEWKEY" in creds.read_text(encoding="utf-8")


# --- _poll_github_token ----------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_poll_continues_on_authorization_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    """`authorization_pending` keeps polling until the token arrives — kills `==` -> `!=` on the
    pending check (the mutant would abort with 'Auth failed')."""
    monkeypatch.setattr(auth.time, "sleep", lambda _s: None)
    monkeypatch.setattr(auth.time, "time", lambda: 1000.0)
    monkeypatch.setattr(httpx, "post", _FakePost([{"error": "authorization_pending"}, {"access_token": "tok123"}]))
    assert _poll_github_token("cid", "dcode", 1) == "tok123"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_poll_continues_on_slow_down(monkeypatch: pytest.MonkeyPatch) -> None:
    """`slow_down` backs off and keeps polling — kills `==` -> `!=` on the slow_down check."""
    monkeypatch.setattr(auth.time, "sleep", lambda _s: None)
    monkeypatch.setattr(auth.time, "time", lambda: 1000.0)
    monkeypatch.setattr(httpx, "post", _FakePost([{"error": "slow_down"}, {"access_token": "tok456"}]))
    assert _poll_github_token("cid", "dcode", 1) == "tok456"


# --- _handle_exchange_response ---------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_exchange_no_waitlist_branch_left() -> None:
    """Every sign-in issues a free key immediately — there is no wait state.
    A `waitlist` error token (from a stale/legacy server) is not a special
    case; it falls through to the same 'no api_key' guard any other
    unrecognized body hits."""
    with pytest.raises(typer.Exit) as exc:
        _handle_exchange_response({"error": "waitlist", "github_login": "octocat"})
    assert exc.value.exit_code == 1


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_exchange_success_never_says_beta_or_full_diagnostics(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A free sign-in never says 'Welcome to the beta' or 'Full diagnostics
    unlocked' — unpaid tiers get no server fix text, and that promise
    undercuts the Pro upgrade at the conversion moment."""
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    _handle_exchange_response({"api_key": "rr_key", "github_login": "octocat", "tier": "free"})
    output = capsys.readouterr().out
    assert "beta" not in output.lower()
    assert "full diagnostics" not in output.lower()
    assert "signed in as" in output.lower()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_exchange_free_key_gets_the_upgrade_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A free-tier sign-in keeps the one-line Pro pitch — matching what an
    unpaid `ails check` run already shows in place of server fix text."""
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    _handle_exchange_response({"api_key": "rr_key", "github_login": "octocat", "tier": "free"})
    output = capsys.readouterr().out
    assert "Pro adds fix text" in output
    assert "Fixes are in the JSON output" not in output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_exchange_pro_key_gets_no_upgrade_pitch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A Pro or team key sign-in must not print the Pro-upgrade pitch — the key
    already has what the pitch is selling."""
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    _handle_exchange_response({"api_key": "rr_key", "github_login": "octocat", "tier": "pro"})
    output = capsys.readouterr().out
    assert "Pro adds fix text" not in output
    assert "Upgrade to Pro" not in output
    assert "Fixes are in the JSON output" in output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_exchange_team_key_gets_no_upgrade_pitch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A team key is entitled the same as pro — no upgrade pitch either."""
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    _handle_exchange_response({"api_key": "rr_key", "github_login": "octocat", "tier": "team"})
    output = capsys.readouterr().out
    assert "Pro adds fix text" not in output


# --- login option/URL handling ---------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_platform_url_option_is_hidden() -> None:
    """`--platform-url` is a hidden option, absent from help — kills `hidden=True` -> `False`."""
    result = runner.invoke(auth_app, ["login", "--help"])
    assert "--platform-url" not in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_uses_explicit_platform_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit `--platform-url` overrides the default — kills `platform_url or _get_platform_url()`
    `or` -> `and` (which would discard the explicit value)."""
    recorded: dict[str, str] = {}

    def _fake_resolve(base_url: str) -> str:
        recorded["url"] = base_url
        raise PlatformUnavailableError("stop early")

    monkeypatch.delenv("AILS_PLATFORM_URL", raising=False)
    monkeypatch.setattr(auth, "_resolve_client_id", _fake_resolve)
    runner.invoke(auth_app, ["login", "--platform-url", "http://custom.example"])
    assert recorded["url"] == "http://custom.example"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_token_help_does_not_leak_the_internal_module_name() -> None:
    """`ails auth token --help` must not name the internal `api_client.py`
    module — public help text never names internal implementation files."""
    result = runner.invoke(auth_app, ["token", "--help"])
    assert "api_client.py" not in result.output


# --- status/token honor AILS_API_KEY (env wins over the credentials file) --


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_status_authenticates_via_env_key_with_no_credentials_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`ails auth status` with `AILS_API_KEY` set and no credentials file must NOT
    say "Not authenticated" — `ails check` in the same shell authenticates via this
    same env var (api_client.py:146), so `auth status` must agree."""
    monkeypatch.setattr(auth, "credentials_path", lambda: tmp_path / "credentials.yml")
    monkeypatch.setenv("AILS_API_KEY", "rr_localtest_pro_0123456789abcdef")
    result = runner.invoke(auth_app, ["status"])
    assert "Not authenticated" not in result.output
    assert "env AILS_API_KEY" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_status_never_shows_bare_at_placeholder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An env-only key with no matching stored identity has no local github
    handle to show — `auth status` must not render the literal `@?`
    placeholder, which reads as a broken f-string."""
    monkeypatch.setattr(auth, "credentials_path", lambda: tmp_path / "credentials.yml")
    monkeypatch.setenv("AILS_API_KEY", "rr_localtest_free_0123456789abcdef")
    result = runner.invoke(auth_app, ["status"])
    assert "@?" not in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_status_does_not_claim_identity_is_resolved_at_check_time(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An env-only key with no local record has no identity to show, and this
    CLI has no way to look one up for a key it did not issue — `auth status`
    must not claim the identity is 'resolved at check time' (only the tier is
    genuinely resolved then, by the server, on a check request)."""
    monkeypatch.setattr(auth, "credentials_path", lambda: tmp_path / "credentials.yml")
    monkeypatch.setenv("AILS_API_KEY", "rr_localtest_free_0123456789abcdef")
    result = runner.invoke(auth_app, ["status"])
    assert "Authenticated as" not in result.output  # no @handle claim of any kind
    assert "@?" not in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_token_prints_env_key_with_no_credentials_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`ails auth token` with `AILS_API_KEY` set and no credentials file must print
    the effective (env) key and exit 0, not exit 1 with "Not authenticated"."""
    monkeypatch.setattr(auth, "credentials_path", lambda: tmp_path / "credentials.yml")
    monkeypatch.setenv("AILS_API_KEY", "rr_localtest_pro_0123456789abcdef")
    result = runner.invoke(auth_app, ["token"])
    assert result.exit_code == 0
    assert result.output.strip() == "rr_localtest_pro_0123456789abcdef"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_token_env_key_wins_over_credentials_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Env wins over the stored file — mirrors api_client.py's own precedence."""
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    auth._write_credentials("rr_from_file", "octocat", "pro")
    monkeypatch.setenv("AILS_API_KEY", "rr_from_env")
    result = runner.invoke(auth_app, ["token"])
    assert result.output.strip() == "rr_from_env"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_status_never_renders_a_legacy_tier_string(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A stored `beta` (or `pro_grandfathered`) tier is a retired legacy string — `auth
    status` must never echo it verbatim; it falls back to the server-resolved message."""
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    monkeypatch.delenv("AILS_API_KEY", raising=False)
    auth._write_credentials("rr_key", "octocat", "beta")
    result = runner.invoke(auth_app, ["status"])
    assert "Tier: beta" not in result.output
    assert "beta" not in result.output.lower()
    assert "resolved at check time" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_status_shows_valid_stored_tier(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A settled stored tier (`free`/`pro`/`team`) IS safe to echo verbatim."""
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    monkeypatch.delenv("AILS_API_KEY", raising=False)
    auth._write_credentials("rr_key", "octocat", "pro")
    result = runner.invoke(auth_app, ["status"])
    assert "Tier: pro" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_persists_no_tier_when_the_server_omits_one(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A server response with no `tier` must write an EMPTY tier, not a stand-in.

    The retired `beta` default persisted a claim nobody made, and every later
    `auth status` echoed it for the life of the credentials file.
    """
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    _handle_exchange_response({"api_key": "rr_key", "github_login": "octocat"})

    assert auth._read_credentials()["tier"] == ""


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_echo_of_an_existing_session_filters_a_legacy_tier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The already-authenticated line goes through the SAME filter `status` uses.

    A stored `beta` used to reach the user as "Beta tier" — a tier that no longer
    exists, title-cased into something that reads authoritative.
    """
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    monkeypatch.setattr(auth, "_resolve_client_id", lambda _base: "cid")
    auth._write_credentials("rr_key", "octocat", "beta")
    result = runner.invoke(auth_app, ["login"])

    assert "Already authenticated as" in result.output
    assert "beta" not in result.output.lower()
    assert "tier" not in result.output.lower()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_echo_of_an_existing_session_keeps_a_known_tier(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    monkeypatch.setattr(auth, "_resolve_client_id", lambda _base: "cid")
    auth._write_credentials("rr_key", "octocat", "team")
    result = runner.invoke(auth_app, ["login"])

    assert "(team tier)" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_already_enrolled_echo_filters_a_legacy_tier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    auth._write_credentials("rr_key", "octocat", "pro")
    with pytest.raises(typer.Exit):
        _handle_exchange_response({"already_enrolled": True, "github_login": "octocat", "tier": "beta"})

    out = capsys.readouterr().out
    assert "Already enrolled as" in out
    assert "beta" not in out.lower()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_already_enrolled_without_a_local_key_points_to_a_new_key_on_the_account_page(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(auth, "credentials_path", lambda: tmp_path / "credentials.yml")
    with pytest.raises(typer.Exit):
        _handle_exchange_response({"already_enrolled": True, "github_login": "octocat", "tier": "pro"})

    out = capsys.readouterr().out
    assert "AILS_API_KEY" in out
    assert "reporails.com/account" in out
    assert "re-register" not in out
    assert "Contact support" not in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_logout_does_not_clear_env_var_and_says_so(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`auth logout` only clears the on-disk file; it never touches the environment,
    and tells the user their env override is still live."""
    creds_path = tmp_path / "credentials.yml"
    monkeypatch.setattr(auth, "credentials_path", lambda: creds_path)
    auth._write_credentials("rr_key", "octocat", "pro")
    monkeypatch.setenv("AILS_API_KEY", "rr_from_env")
    result = runner.invoke(auth_app, ["logout"])
    assert not creds_path.exists()
    assert os.environ.get("AILS_API_KEY") == "rr_from_env"  # untouched
    assert "AILS_API_KEY" in result.output
