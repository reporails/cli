"""ails login / ails logout: sign this machine in to your account through the browser.

The sign-in is stored in ~/.reporails/credentials.yml (not in the project).
"""

from __future__ import annotations

import logging
import math
import os
import socket
import sys
import time
import webbrowser
from datetime import UTC, datetime
from urllib.parse import urlparse

import typer
from rich.markup import escape

from reporails_cli.core.platform.adapters.key_check import check_api_key
from reporails_cli.core.platform.adapters.notices_seen import due_notices
from reporails_cli.core.platform.adapters.sign_in import poll_sign_in, revoke_sign_in, start_sign_in
from reporails_cli.core.platform.config.credentials import (
    clear_credentials,
    credentials_path,
    env_api_key,
    load_credentials_record,
    read_credentials,
    signed_in_recently,
    write_credentials_file,
)
from reporails_cli.core.platform.config.endpoints import platform_url
from reporails_cli.core.platform.contract.errors import CredentialsUnreadableError, PlatformError, PlatformRefusedError
from reporails_cli.core.platform.dto.diagnostics import ENTITLED_TIERS, STILL_REACHING_MESSAGE, Notice, tier_label
from reporails_cli.core.platform.dto.sign_in import SignedIn, SignInGrant
from reporails_cli.formatters.text.funnel_cta import UNPAID_PITCH_LINE, upgrade_link_line
from reporails_cli.formatters.text.notices import print_notices
from reporails_cli.interfaces.cli.helpers import app, console

logger = logging.getLogger(__name__)

# Seconds added to the wait between asks when the website says they come too fast.
_SLOW_DOWN_S = 5
# Seconds in a minute, and the wait named when the website sends none (ten minutes).
_MINUTE_S = 60
_DEFAULT_WAIT_S = 600
_RATE_LIMITED = 429
_EXPIRED_MSG = "The sign-in link expired. Run `ails login` again. Nothing was saved."
_ENDED_MESSAGES = {
    "denied": "Sign-in was denied in the browser. Nothing was saved.",
    "expired": _EXPIRED_MSG,
}


def _tier_phrase(tier: str) -> str:
    """` (Pro)` for a tier the sign-in names (Free, Pro, Team); "" for anything else."""
    return f" ({tier_label(tier)})" if tier_label(tier) else ""


def _signed_in_line(account: str, tier: str) -> str:
    """`Signed in as @account (Tier)`, or `Signed in on this machine (Tier)` without an account."""
    who = f"as [bold]@{escape(account)}[/bold]" if account else "on this machine"
    return f"  [green]Signed in[/green] {who}{_tier_phrase(tier)}"


def _print_notices(notices: tuple[Notice, ...]) -> None:
    """The notices not yet shown today, as the server worded them."""
    print_notices(console, due_notices(notices))


def _note_env_override(saved_key: str) -> None:
    """Say so when `AILS_API_KEY` holds a different key, which ails uses instead of the sign-in."""
    env_key = env_api_key()
    if env_key and env_key != saved_key:
        console.print(
            "  [yellow]AILS_API_KEY is set in this shell and is used instead of your sign-in;[/yellow] "
            "unset it to use the sign-in."
        )


def _print_tier_lines(tier: str) -> None:
    """What the account's tier means for the next run: the upgrade lines, or where rewriting runs."""
    if tier in ENTITLED_TIERS:
        console.print("  Rewriting your instruction files runs in your coding agent.")
        console.print(
            "  [bold]ails install[/bold] adds the plugin, then run [bold]/reporails:ails heal[/bold] in Claude Code."
        )
        return
    console.print("  Your diagnosis is unchanged; [bold]ails check --heal[/bold] now applies formatting fixes.")
    console.print(UNPAID_PITCH_LINE)
    console.print(upgrade_link_line())


def _note_rejected(stored_key: str) -> None:
    """Say the stored sign-in ended; exit 0 instead when it was made moments ago and is still arriving."""
    if signed_in_recently(stored_key):
        console.print(f"  {STILL_REACHING_MESSAGE}")
        raise typer.Exit(0)
    console.print("  Your sign-in on this machine ended; signing in again.")


def _confirm_stored_sign_in(record: dict[str, str]) -> None:
    """Check the stored sign-in with the server. Returns only when it was rejected; otherwise exits 0."""
    stored_key = record["api_key"]
    account = record.get("account", "")
    result = check_api_key(stored_key)
    if result.status == "rejected":
        _note_rejected(stored_key)
        return
    if result.status == "unavailable":
        console.print(f"{_signed_in_line(account, record.get('tier', ''))} (could not reach the server to confirm)")
        raise typer.Exit(0)
    console.print(_signed_in_line(account, result.tier))
    _print_notices(result.notices)
    _note_env_override(stored_key)
    raise typer.Exit(0)


def _refusal_line(exc: PlatformRefusedError) -> str:
    """One line for a start the website refused: the wait for a rate limit, the status otherwise."""
    if exc.status == _RATE_LIMITED:
        minutes = math.ceil((exc.retry_after or _DEFAULT_WAIT_S) / _MINUTE_S)
        return f"Too many sign-in attempts from this network. Try again in {minutes} minutes."
    return f"The website refused to start a sign-in (HTTP {exc.status}). Nothing was saved."


def _start(site: str) -> SignInGrant:
    """Start a sign-in; exit 1 with one line when the website refuses or cannot be reached."""
    try:
        return start_sign_in(site, socket.gethostname())
    except PlatformRefusedError as exc:
        console.print(f"  {_refusal_line(exc)}")
        raise typer.Exit(1) from exc
    except PlatformError as exc:
        host = escape(urlparse(site).hostname or site)
        console.print(f"  Could not reach {host} — nothing was saved. Try again shortly.")
        raise typer.Exit(1) from exc


def _can_show_browser() -> bool:
    """True when a person is at the terminal and a graphical session can show a page."""
    if not sys.stdout.isatty():
        return False
    return not sys.platform.startswith("linux") or bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _show_link(grant: SignInGrant) -> None:
    """Print the link and the code, and open the link when a person is at the terminal."""
    console.print(f"  Open this link to sign in: {escape(grant.verification_url)}", soft_wrap=True)
    console.print(f"  Code: [bold]{escape(grant.user_code)}[/bold], check it matches the page")
    if not _can_show_browser():
        return
    try:
        webbrowser.open(grant.verification_url)
    except (webbrowser.Error, OSError) as exc:
        # Best effort: the link is already printed, so a missing browser costs nothing.
        logger.debug("Could not open the browser: %s", exc)


def _wait_for_sign_in(site: str, grant: SignInGrant) -> SignedIn:
    """Ask the website every `interval` seconds until the sign-in finishes; exit 1 when it does not."""
    interval = grant.interval
    deadline = time.monotonic() + grant.expires_in
    while time.monotonic() < deadline:
        time.sleep(interval)
        outcome = poll_sign_in(site, grant.device_code)
        if outcome.status == "signed_in" and outcome.signed_in is not None:
            return outcome.signed_in
        if outcome.status == "slow_down":
            interval += _SLOW_DOWN_S
        elif outcome.status in _ENDED_MESSAGES:
            console.print(f"  {_ENDED_MESSAGES[outcome.status]}")
            raise typer.Exit(1)
        elif outcome.status == "failed":
            console.print(f"  Sign-in failed ({escape(outcome.code)}). Nothing was saved.")
            raise typer.Exit(1)
    console.print(f"  {_EXPIRED_MSG}")
    raise typer.Exit(1)


def _save(signed_in: SignedIn) -> None:
    """Store the sign-in; exit 1 with one line when the file cannot be written."""
    record = {
        "api_key": signed_in.access_token,
        "account": signed_in.login,
        "tier": signed_in.tier,
        "signed_in_at": datetime.now(UTC).isoformat(),
    }
    try:
        write_credentials_file(credentials_path(), record)
    except OSError as exc:
        console.print(f"  Could not save the sign-in to {escape(str(credentials_path()))}: {escape(str(exc))}")
        raise typer.Exit(1) from exc


def _sign_in_through_browser(site: str) -> SignedIn:
    """Run the browser sign-in; exit 1 on a refusal or timeout, 130 on Ctrl-C."""
    grant = _start(site)
    _show_link(grant)
    try:
        return _wait_for_sign_in(site, grant)
    except KeyboardInterrupt as exc:
        console.print("  Sign-in cancelled. Nothing was saved.")
        raise typer.Exit(130) from exc


@app.command("login", rich_help_panel="Account & setup")
def login() -> None:
    """Sign this machine in to your account through the browser."""
    record = read_credentials()
    if record.get("api_key"):
        _confirm_stored_sign_in(record)
    signed_in = _sign_in_through_browser(platform_url())
    _save(signed_in)
    console.print(_signed_in_line(signed_in.login, signed_in.tier))
    _print_notices(signed_in.notices)
    _print_tier_lines(signed_in.tier)
    _note_env_override(signed_in.access_token)


@app.command("logout", rich_help_panel="Account & setup")
def logout() -> None:
    """Sign this machine out."""
    try:
        record = load_credentials_record()
    except CredentialsUnreadableError:
        clear_credentials()
        console.print("  Logged out on this machine.")
        _note_env_still_authenticates()
        raise typer.Exit(0) from None
    token = record.get("api_key", "")
    if not token:
        console.print("  Not signed in on this machine.")
        _note_env_still_authenticates()
        raise typer.Exit(0)
    revoked = True
    # Only a sign-in `ails login` made is revoked on the server: a key file without
    # `signed_in_at` may be a key the account also uses elsewhere.
    if record.get("signed_in_at"):
        try:
            revoke_sign_in(platform_url(), token)
        except PlatformError:
            revoked = False
    clear_credentials()
    console.print("  Logged out on this machine.")
    if not revoked:
        console.print("  The sign-in could not be revoked on the server; revoke it on reporails.com/account.")
    _note_env_still_authenticates()


def _note_env_still_authenticates() -> None:
    """Say so when `AILS_API_KEY` is set: logging out does not stop it authenticating ails commands."""
    if env_api_key():
        console.print("  [yellow]AILS_API_KEY[/yellow] is set in this shell and still authenticates ails commands.")
