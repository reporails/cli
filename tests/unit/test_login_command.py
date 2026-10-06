"""`ails login` and `ails logout`: the real app, with the website, the server and the browser stubbed."""

from __future__ import annotations

import stat
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from reporails_cli.core.platform.config.credentials import credentials_path, read_credentials
from reporails_cli.core.platform.contract.errors import PlatformRefusedError, PlatformUnavailableError
from reporails_cli.core.platform.dto.diagnostics import STILL_REACHING_MESSAGE, Notice
from reporails_cli.core.platform.dto.sign_in import KeyCheck, PollOutcome, SignedIn, SignInGrant
from reporails_cli.interfaces.cli import login_command
from reporails_cli.interfaces.cli.main import app

runner = CliRunner(env={"COLUMNS": "200"})  # no line wrapping inside the asserted sentences
_GRANT = SignInGrant("dev-1", "ABCD-EFGH", "https://reporails.com/oauth/device?user_code=ABCD-EFGH", 600, 5)


def _signed_in(tier: str = "free", notices: tuple[Notice, ...] = ()) -> PollOutcome:
    return PollOutcome("signed_in", SignedIn("tok-new", "octo", tier, "laptop", notices))


class _Site:
    """The website, the diagnostics server and the clock as the command sees them."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []
        self.polls: list[PollOutcome] = []
        self.poll_calls = 0
        self.start_error: Exception | None = None
        self.check = KeyCheck("unavailable", reason="offline")
        self.checked_keys: list[str] = []
        self.revoked: list[str] = []
        self.revoke_error: Exception | None = None
        self.opened: list[str] = []
        self.grant = _GRANT
        monkeypatch.setattr(login_command.time, "sleep", self._sleep)
        monkeypatch.setattr(login_command.time, "monotonic", lambda: self.now)
        monkeypatch.setattr(login_command, "start_sign_in", self._start)
        monkeypatch.setattr(login_command, "poll_sign_in", self._poll)
        monkeypatch.setattr(login_command, "revoke_sign_in", self._revoke)
        monkeypatch.setattr(login_command, "check_api_key", self._check)
        monkeypatch.setattr(login_command, "_open_in_browser", self.opened.append)

    def _sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def _start(self, site: str, machine: str) -> SignInGrant:
        if self.start_error:
            raise self.start_error
        return self.grant

    def _poll(self, site: str, device_code: str) -> PollOutcome:
        self.poll_calls += 1
        return self.polls.pop(0) if self.polls else PollOutcome("pending")

    def _revoke(self, site: str, token: str) -> None:
        self.revoked.append(token)
        if self.revoke_error:
            raise self.revoke_error

    def _check(self, key: str) -> KeyCheck:
        self.checked_keys.append(key)
        return self.check


# The autouse fixture in conftest already clears the CI variables.
_ENV_THAT_DECIDES = ("DISPLAY", "WAYLAND_DISPLAY", "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "BROWSER")


class _FakeSys:
    """`sys` for the command with one thing changed: the platform."""

    def __init__(self, platform: str) -> None:
        self.platform = platform

    def __getattr__(self, name: str) -> object:
        return getattr(sys, name)


def _on_platform(monkeypatch: pytest.MonkeyPatch, platform: str = "darwin") -> None:
    """Run the command on `platform`, with no screen and no SSH session unless the test sets one."""
    for name in _ENV_THAT_DECIDES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(login_command, "sys", _FakeSys(platform))


@pytest.fixture
def site(monkeypatch: pytest.MonkeyPatch) -> _Site:
    return _Site(monkeypatch)


def _store(record: dict[str, str]) -> Path:
    path = credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(record), encoding="utf-8")
    return path


_LOGIN_RECORD = {"api_key": "tok-old", "account": "octo", "tier": "free", "signed_in_at": "2026-10-01T00:00:00+00:00"}


# --- login: a fresh sign-in -------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_saves_the_credential_and_reports(site: _Site) -> None:
    site.polls = [_signed_in("free")]
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 0
    assert "Signed in as @octo (Free)" in result.output
    assert _GRANT.verification_url in result.output
    assert "ABCD-EFGH" in result.output
    stored = yaml.safe_load(credentials_path().read_text(encoding="utf-8"))
    assert {k: stored[k] for k in ("api_key", "account", "tier")} == {
        "api_key": "tok-new",
        "account": "octo",
        "tier": "free",
    }
    assert stored["signed_in_at"].endswith("+00:00")
    if sys.platform != "win32":  # POSIX mode bits are not enforced on Windows
        assert stat.S_IMODE(credentials_path().stat().st_mode) == 0o600
    assert read_credentials()["api_key"] == "tok-new"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_polls_pending_then_slow_down_then_success(site: _Site) -> None:
    site.polls = [PollOutcome("pending"), PollOutcome("slow_down"), PollOutcome("retry"), _signed_in("pro")]
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 0
    assert site.sleeps == [5, 5, 10, 10]  # the wait grows by five seconds after a slow_down
    assert "Signed in as @octo (Pro)" in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("platform", "env", "opens"),
    [
        ("linux", {}, False),
        ("linux", {"DISPLAY": ":0"}, True),
        ("linux", {"WAYLAND_DISPLAY": "wayland-0"}, True),
        ("darwin", {}, True),
        ("win32", {}, True),
        ("freebsd", {}, False),
        ("darwin", {"SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 22"}, False),
        ("win32", {"SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 22"}, False),
        ("linux", {"SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 22", "DISPLAY": "localhost:10.0"}, True),
        ("darwin", {"SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 22", "DISPLAY": "localhost:10.0"}, False),
        ("linux", {"SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 22", "BROWSER": "wslview"}, True),
        ("linux", {"BROWSER": "  "}, False),
        ("darwin", {"CI": "true"}, False),
        ("linux", {"CI": "true", "DISPLAY": ":0"}, False),
    ],
)
def test_login_opens_the_browser_only_where_a_screen_can_show_it(
    site: _Site, monkeypatch: pytest.MonkeyPatch, platform: str, env: dict[str, str], opens: bool
) -> None:
    _on_platform(monkeypatch, platform)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    site.polls = [_signed_in()]
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 0
    assert _GRANT.verification_url in result.output
    assert site.opened == ([_GRANT.verification_url] if opens else [])


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_ignores_a_browser_that_will_not_open(site: _Site, monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(url: str) -> None:
        raise OSError("no browser")

    _on_platform(monkeypatch)
    monkeypatch.setattr(login_command, "_open_in_browser", _fail)
    site.polls = [_signed_in()]
    assert runner.invoke(app, ["login"]).exit_code == 0


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_the_page_opens_in_a_real_child_that_ignores_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "marker.txt"
    program = tmp_path / "marker.py"
    program.write_text(
        f"import sys\nwith open({marker.as_posix()!r}, 'a') as out:\n    out.write(sys.argv[1])\n", encoding="utf-8"
    )
    shadowed = tmp_path / "shadowed.txt"
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "webbrowser.py").write_text(f"open({shadowed.as_posix()!r}, 'w').write('x')\n", encoding="utf-8")
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("BROWSER", f'"{Path(sys.executable).as_posix()}" "{program.as_posix()}" %s')
    login_command._open_in_browser("https://reporails.com/x")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not (marker.exists() or shadowed.exists()):
        time.sleep(0.05)
    time.sleep(0.2)  # let a wrongly imported file finish writing
    assert marker.read_text(encoding="utf-8") == "https://reporails.com/x"
    assert not shadowed.exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/oauth/device?user_code=ABCD-EFGH",
        "http://reporails.com/oauth/device?user_code=ABCD-EFGH",
        "file:///etc/passwd",
        "https://reporails.com/oauth/device\x00?user_code=ABCD-EFGH",
        "https://reporails.com/oauth/device\x1b[2J",
    ],
)
def test_login_never_opens_a_link_that_is_not_the_websites(
    site: _Site, monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    _on_platform(monkeypatch)
    site.grant = SignInGrant("dev-1", "ABCD-EFGH", url, 600, 5)
    site.polls = [_signed_in()]
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 0
    assert "ABCD-EFGH" in result.output
    assert site.opened == []


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("outcome", "message"),
    [
        (PollOutcome("denied"), "Sign-in was denied in the browser. Nothing was saved."),
        (PollOutcome("expired"), "The sign-in link expired. Run `ails login` again. Nothing was saved."),
        (PollOutcome("failed", code="server_error"), "Sign-in failed (server_error). Nothing was saved."),
    ],
)
def test_login_that_ends_saves_nothing(site: _Site, outcome: PollOutcome, message: str) -> None:
    site.polls = [PollOutcome("pending"), outcome]
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 1
    assert message in result.output
    assert not credentials_path().exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_stops_at_the_deadline(site: _Site) -> None:
    result = runner.invoke(app, ["login"])  # the website never answers anything but pending
    assert result.exit_code == 1
    assert "The sign-in link expired. Run `ails login` again. Nothing was saved." in result.output
    assert site.poll_calls == 120  # 600 s deadline at one ask every 5 s
    assert not credentials_path().exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_start_failure_names_what_to_do(site: _Site) -> None:
    site.start_error = PlatformUnavailableError("down")
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 1
    assert "Could not reach reporails.com" in result.output
    assert "nothing was saved. Try again shortly." in result.output
    assert site.poll_calls == 0
    assert not credentials_path().exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("error", "line"),
    [
        (
            PlatformRefusedError("x", status=429, retry_after=600),
            "Too many sign-in attempts from this network. Try again in 10 minutes.",
        ),
        (PlatformRefusedError("x", status=429, retry_after=61), "Try again in 2 minutes."),
        (PlatformRefusedError("x", status=429), "Try again in 10 minutes."),
        (
            PlatformRefusedError("x", status=503),
            "The website refused to start a sign-in (HTTP 503). Nothing was saved.",
        ),
    ],
)
def test_login_start_refusal_says_why(site: _Site, error: PlatformRefusedError, line: str) -> None:
    site.start_error = error
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 1
    assert line in result.output
    assert not credentials_path().exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_unreachable_names_the_overridden_website(site: _Site, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_PLATFORM_URL", "http://127.0.0.1:9")
    site.start_error = PlatformUnavailableError("down")
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 1
    assert "Could not reach 127.0.0.1 — nothing was saved." in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_ctrl_c_cancels_without_saving(site: _Site, monkeypatch: pytest.MonkeyPatch) -> None:
    def _interrupt(site_url: str, device_code: str) -> PollOutcome:
        raise KeyboardInterrupt

    monkeypatch.setattr(login_command, "poll_sign_in", _interrupt)
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 130
    assert "Sign-in cancelled. Nothing was saved." in result.output
    assert not credentials_path().exists()


# --- login: what the report says --------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_free_login_prints_the_upgrade_lines(site: _Site) -> None:
    site.polls = [_signed_in("free")]
    out = runner.invoke(app, ["login"]).output
    assert "Pro adds the remedies and the order to apply them." in out
    assert "Upgrade to Pro" in out
    assert "/reporails:ails heal" not in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(("tier", "label"), [("pro", "Pro"), ("team", "Team")])
def test_entitled_login_prints_the_pro_lines_and_no_pitch(site: _Site, tier: str, label: str) -> None:
    site.polls = [_signed_in(tier)]
    out = runner.invoke(app, ["login"]).output
    assert f"Signed in as @octo ({label})" in out
    assert "/reporails:ails heal" in out
    assert "Pro adds the remedies" not in out
    assert "Upgrade to Pro" not in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_an_unknown_tier_adds_no_parenthetical(site: _Site) -> None:
    site.polls = [_signed_in("beta")]
    out = runner.invoke(app, ["login"]).output
    assert "Signed in as @octo" in out
    assert "(Beta)" not in out
    assert "(beta)" not in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_prints_notices_escaped(site: _Site) -> None:
    notice = Notice("n1", "info", "Read [bold]this[/bold] first", "https://reporails.com/n")
    site.polls = [_signed_in("free", (notice,))]
    out = runner.invoke(app, ["login"]).output
    assert "Read [bold]this[/bold] first" in out
    assert "https://reporails.com/n" in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_an_account_name_is_never_read_as_markup(site: _Site) -> None:
    site.polls = [PollOutcome("signed_in", SignedIn("tok-new", "a[/]b", "free"))]
    assert "@a[/]b" in runner.invoke(app, ["login"]).output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_notes_a_different_env_key(site: _Site, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_API_KEY", "rr_other")
    site.polls = [_signed_in()]
    out = runner.invoke(app, ["login"]).output
    assert "AILS_API_KEY is set in this shell and is used instead of your sign-in;" in out
    assert "unset it to use the sign-in." in out


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_says_nothing_about_an_env_key_that_is_the_credential(
    site: _Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AILS_API_KEY", "tok-new")
    site.polls = [_signed_in()]
    assert "AILS_API_KEY" not in runner.invoke(app, ["login"]).output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_does_not_check_the_new_credential_with_the_server(site: _Site) -> None:
    site.polls = [_signed_in()]
    runner.invoke(app, ["login"])
    assert site.checked_keys == []


# --- login: already signed in -----------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_when_signed_in_and_accepted_echoes_the_server_tier(site: _Site) -> None:
    _store(_LOGIN_RECORD)
    site.check = KeyCheck("accepted", tier="pro", notices=(Notice("n2", "warn", "Heads up", ""),))
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 0
    assert "Signed in as @octo (Pro)" in result.output  # the server's tier, not the stored "free"
    assert "Heads up" in result.output
    assert site.checked_keys == ["tok-old"]
    assert site.poll_calls == 0
    assert read_credentials()["api_key"] == "tok-old"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_when_signed_in_without_an_account_name(site: _Site) -> None:
    _store({"api_key": "tok-old", "tier": "free"})
    site.check = KeyCheck("accepted", tier="free")
    assert "Signed in on this machine (Free)" in runner.invoke(app, ["login"]).output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_when_signed_in_notes_a_different_env_key(site: _Site, monkeypatch: pytest.MonkeyPatch) -> None:
    _store(_LOGIN_RECORD)
    monkeypatch.setenv("AILS_API_KEY", "rr_other")
    site.check = KeyCheck("accepted", tier="free")
    assert "AILS_API_KEY is set in this shell" in runner.invoke(app, ["login"]).output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_when_the_stored_sign_in_was_rejected_signs_in_again(site: _Site) -> None:
    _store(_LOGIN_RECORD)
    site.check = KeyCheck("rejected", error="invalid_api_key")
    site.polls = [_signed_in("pro")]
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 0
    assert "Your sign-in on this machine ended; signing in again." in result.output
    assert "Signed in as @octo (Pro)" in result.output
    assert read_credentials()["api_key"] == "tok-new"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_when_a_new_sign_in_is_rejected_does_not_start_another(site: _Site) -> None:
    just_now = {**_LOGIN_RECORD, "signed_in_at": datetime.now(UTC).isoformat()}
    _store(just_now)
    site.check = KeyCheck("rejected", error="invalid_api_key")
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 0
    assert STILL_REACHING_MESSAGE in result.output
    assert site.poll_calls == 0
    assert read_credentials()["api_key"] == "tok-old"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_when_the_server_is_unreachable_keeps_the_stored_sign_in(site: _Site) -> None:
    _store(_LOGIN_RECORD)
    result = runner.invoke(app, ["login"])
    assert result.exit_code == 0
    assert "Signed in as @octo (Free)" in result.output
    assert "(could not reach the server to confirm)" in result.output
    assert site.poll_calls == 0
    assert read_credentials()["api_key"] == "tok-old"


# --- logout -----------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_logout_revokes_a_sign_in_made_by_login_then_deletes_the_file(site: _Site) -> None:
    path = _store(_LOGIN_RECORD)
    result = runner.invoke(app, ["logout"])
    assert result.exit_code == 0
    assert site.revoked == ["tok-old"]
    assert "Logged out on this machine." in result.output
    assert "could not be revoked" not in result.output
    assert not path.exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_logout_never_sends_an_older_key_file_to_the_server(site: _Site) -> None:
    path = _store({"api_key": "rr_ci_key", "github_login": "octocat", "tier": "pro"})
    result = runner.invoke(app, ["logout"])
    assert result.exit_code == 0
    assert site.revoked == []  # that key may be the account's CI key
    assert "Logged out on this machine." in result.output
    assert not path.exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_logout_with_the_server_down_still_deletes_the_file_and_says_so(site: _Site) -> None:
    site.revoke_error = PlatformUnavailableError("down")
    path = _store(_LOGIN_RECORD)
    result = runner.invoke(app, ["logout"])
    assert result.exit_code == 0
    assert not path.exists()
    assert "Logged out on this machine." in result.output
    assert "The sign-in could not be revoked on the server; revoke it on reporails.com/account." in result.output


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_logout_removes_a_file_that_cannot_be_read_without_asking_the_server(site: _Site) -> None:
    path = _store(_LOGIN_RECORD)
    path.write_text("api_key: [\n", encoding="utf-8")
    result = runner.invoke(app, ["logout"])
    assert result.exit_code == 0
    assert "Logged out on this machine." in result.output
    assert site.revoked == []
    assert not path.exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_logout_when_not_signed_in(site: _Site) -> None:
    result = runner.invoke(app, ["logout"])
    assert result.exit_code == 0
    assert "Not signed in on this machine." in result.output
    assert "AILS_API_KEY" not in result.output
    assert site.revoked == []


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_logout_names_an_env_key_that_still_authenticates(site: _Site, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_API_KEY", "rr_env")
    out = runner.invoke(app, ["logout"]).output
    assert "Not signed in on this machine." in out
    assert "AILS_API_KEY" in out
    path = _store(_LOGIN_RECORD)
    result = runner.invoke(app, ["logout"])
    assert not path.exists()
    assert "Logged out on this machine." in result.output
    assert "still authenticates ails commands" in result.output
    assert login_command.env_api_key() == "rr_env"  # never touched


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_the_old_auth_group_is_gone() -> None:
    assert runner.invoke(app, ["auth", "login"]).exit_code == 2


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_login_and_logout_are_listed_in_account_and_setup() -> None:
    panels = {c.name: c.rich_help_panel for c in app.registered_commands}
    assert panels["login"] == panels["logout"] == "Account & setup"
