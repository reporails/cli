"""ails auth — authenticate with the Reporails platform.

Supports GitHub Device Flow for terminal-based authentication.
The API key is stored in ~/.reporails/credentials.yml (not in the project).
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import typer
import yaml
from rich.console import Console

from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from reporails_cli.core.platform.dto.diagnostics import ENTITLED_TIERS, UNENTITLED_TIERS

logger = logging.getLogger(__name__)

console = Console(emoji=False, highlight=False)
auth_app = typer.Typer(
    name="auth",
    help="Authenticate with the Reporails platform.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

# GitHub OAuth App Client ID — public, embedded in CLI.
# This is NOT a secret. GitHub Device Flow requires the client ID
# to be available client-side.
GITHUB_CLIENT_ID = ""  # Always sourced from the platform — see _resolve_client_id() below.

# Reporails platform URL — configurable for local dev
DEFAULT_PLATFORM_URL = "https://reporails.com"


def _user_agent() -> str:
    """User-Agent string for outbound auth requests to the platform.

    Stable, identifiable UA lets edge allow/Skip rules target CLI traffic by
    User-Agent — important when bot mitigation is tightened and clients
    classified as "definitely automated" otherwise hit a JS challenge.
    """
    from reporails_cli import __version__

    return f"reporails-cli/{__version__} (auth)"


def _credentials_path() -> Path:
    """Path to credentials file."""
    return Path.home() / ".reporails" / "credentials.yml"


def _read_credentials() -> dict[str, str]:
    """Read stored credentials."""
    path = _credentials_path()
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (yaml.YAMLError, OSError):
        return {}


def _write_credentials(api_key: str, github_login: str, tier: str) -> None:
    """Store credentials securely.

    The directory and the file are owner-only from their first byte — on
    NTFS (no POSIX mode bits) that guarantee doesn't apply, so Windows keeps
    the whatever-the-filesystem-gives-it default and only warns. On POSIX,
    `os.open` with an explicit mode creates the file at 0600 directly (a mode
    with no group/other bits, so no umask can widen it), instead of writing
    the plaintext key at the platform default and narrowing it a moment
    later — that gap let a concurrent reader on a shared host see the key.

    The `os.open` mode only applies when the call creates the file: a
    `credentials.yml` already on disk at a wider mode (an older CLI version,
    a restore that dropped permissions) would otherwise keep that mode after
    a fresh key is written. `fchmod` after opening forces 0600 either way,
    new file or existing.
    """
    import os

    path = _credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = yaml.dump(
        {"api_key": api_key, "github_login": github_login, "tier": tier},
        default_flow_style=False,
    )
    if sys.platform == "win32":
        path.write_text(data, encoding="utf-8")
        logger.warning("File permissions not enforced on Windows — secure %s manually", path)
        return
    path.parent.chmod(0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)  # the mode above only took effect if this call created the file
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)


def _clear_credentials() -> None:
    """Remove stored credentials."""
    path = _credentials_path()
    if path.exists():
        path.unlink()


def _get_platform_url() -> str:
    """Get platform URL from env or default."""
    import os

    return os.environ.get("AILS_PLATFORM_URL", DEFAULT_PLATFORM_URL).rstrip("/")


class SignInRefusedError(PlatformUnavailableError):
    """The website answered a sign-in step with a non-2xx status; the message says what to do."""


_REFUSAL_MESSAGES = {
    "user_creation_failed": (
        "Reporails could not create an account for this GitHub login, usually because a "
        "Reporails account already uses this email. Sign in with that account's password at "
        "reporails.com/user/login (or reset it at reporails.com/user/password), then on "
        "reporails.com/account use Regenerate and set the key as AILS_API_KEY. "
        "Otherwise contact us at reporails.com/contact."
    ),
    "invalid_github_token": "GitHub did not accept the sign-in. Run `ails auth login` again.",
    "github_oauth_not_configured": "Sign-in is not available right now. Contact us at reporails.com/contact.",
}


def _refusal_message(status_code: int, body_text: str) -> str:
    """One actionable line for a non-2xx sign-in reply; tolerates a non-JSON body."""
    import json

    try:
        body = json.loads(body_text)
    except (ValueError, TypeError):
        body = None
    code = str(body.get("error", "")) if isinstance(body, dict) else ""
    if code in _REFUSAL_MESSAGES:
        return _REFUSAL_MESSAGES[code]
    if status_code >= 500 or status_code == 429:
        return (
            f"The website did not answer the sign-in (HTTP {status_code}). Run `ails auth login` "
            "again shortly; if it keeps failing, contact us at reporails.com/contact."
        )
    detail = f"HTTP {status_code}: {code}" if code else f"HTTP {status_code}"
    return f"The sign-in was refused ({detail}). Contact us at reporails.com/contact."


def _resolve_client_id(base_url: str) -> str:
    """Resolve the GitHub OAuth client ID, trying embedded constant then platform.

    Raises PlatformUnavailableError when the platform endpoint is reachable but
    returns a non-JSON body (a transient network/proxy state), so that state is
    not reported as a misleading "OAuth not configured" message.
    """
    import httpx

    if GITHUB_CLIENT_ID:
        return GITHUB_CLIENT_ID

    headers = {"User-Agent": _user_agent(), "Accept": "application/json"}
    try:
        resp = httpx.get(f"{base_url}/api/auth/client-id", timeout=5.0, headers=headers)
    except (httpx.HTTPError, OSError) as exc:
        logger.warning("Platform unreachable for client-id resolution: %s", exc)
        raise PlatformUnavailableError(
            f"Cannot reach Reporails platform at {base_url}: {exc}",
        ) from exc

    if resp.status_code != 200:
        logger.warning("Platform returned HTTP %s for client-id", resp.status_code)
        raise SignInRefusedError(_refusal_message(resp.status_code, resp.text))

    try:
        return str(resp.json().get("client_id", ""))
    except ValueError as exc:
        logger.warning("Platform returned non-JSON for client-id: %s", resp.text[:200])
        raise PlatformUnavailableError(
            "Reporails platform returned an unexpected (non-JSON) response for the client-id endpoint — "
            "likely a transient network or edge issue. Retry shortly or contact us at reporails.com/contact.",
        ) from exc


def _poll_github_token(client_id: str, device_code: str, interval: int) -> str | None:
    """Poll GitHub for an access token via device flow. Returns token or None on timeout."""
    import httpx

    deadline = time.time() + 900  # 15 min timeout
    while time.time() < deadline:
        time.sleep(interval)
        try:
            poll = httpx.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": client_id,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
                headers={"Accept": "application/json", "User-Agent": _user_agent()},
                timeout=10.0,
            )
            result = poll.json()
        except (httpx.HTTPError, OSError, ValueError):
            continue

        if "access_token" in result:
            return str(result["access_token"])
        if result.get("error") == "authorization_pending":
            continue
        if result.get("error") == "slow_down":
            interval += 5
            continue

        console.print(f"  [red]Auth failed:[/] {result.get('error', 'unknown error')}")
        raise typer.Exit(1)
    return None


def _handle_exchange_response(payload: dict[str, str]) -> None:
    """Handle the API key exchange response — already enrolled, or success.

    This branches on the reply and on whether a local key already exists only.
    """
    if payload.get("already_enrolled"):
        username = payload.get("github_login", "")
        tier = _tier_phrase(payload.get("tier", ""))
        creds = _read_credentials()
        if creds.get("api_key"):
            console.print(f"  Already enrolled as [bold]@{username}[/]{tier}.")
            console.print("  Your existing key is still active.\n")
        else:
            console.print(f"  [yellow]You're enrolled as @{username}{tier},[/]")
            from reporails_cli.formatters.text.funnel_cta import _SUBSCRIBE_URL

            console.print("  but this machine has no key, and logging in again cannot return it.")
            console.print(
                f"  → Generate a new key on [link={_SUBSCRIBE_URL}]reporails.com/account[/link] "
                "and set it as [bold]AILS_API_KEY[/].\n"
            )
        raise typer.Exit(0)

    api_key = payload.get("api_key")
    if not api_key:
        console.print(f"  [red]Unexpected response from server:[/] {payload}")
        raise typer.Exit(1)

    username = payload.get("github_login", "")
    tier = str(payload.get("tier") or "")
    # No tier from the server means no tier on disk. Writing a stand-in here
    # persists a claim nobody made, and `auth status` then echoes it for the
    # life of the credentials file.
    _write_credentials(api_key, username, tier)

    console.print(f"  [green]Signed in as[/] [bold]@{username}[/]{_tier_phrase(tier)}.")
    console.print("  Your diagnosis is unchanged; [bold]ails check --heal[/bold] is now enabled.")
    if tier in ENTITLED_TIERS:
        # Already paying — no upgrade pitch to a Pro/team key, matching the
        # tier-aware line `ails check` itself shows a Pro run.
        console.print("  [dim]Fixes are in the JSON output (--format json) and the MCP tools.[/dim]\n")
    else:
        # Unpaid tiers get no server fix text; this one line replaces it,
        # matching the line an unpaid `ails check` run shows.
        from reporails_cli.formatters.text.funnel_cta import _SUBSCRIBE_URL

        console.print("  Pro adds fix text for the remaining findings and the order to apply them.")
        console.print(f"  → [link={_SUBSCRIBE_URL}][bold]Upgrade to Pro[/bold] reporails.com/account[/link]\n")


def _exchange_github_token(base_url: str, github_token: str) -> dict[str, str]:
    """POST the GitHub token to the platform; exit 1 with one line on any failure."""
    import httpx

    try:
        exchange = httpx.post(
            f"{base_url}/api/auth/cli-exchange",
            json={"github_token": github_token},
            headers={"Accept": "application/json", "User-Agent": _user_agent()},
            timeout=10.0,
        )
        if not 200 <= exchange.status_code < 300:
            console.print(f"  [red]{_refusal_message(exchange.status_code, exchange.text)}[/]")
            raise typer.Exit(1)
        payload = exchange.json()
        if not isinstance(payload, dict):
            raise ValueError("cli-exchange reply is not a JSON object")
    except ValueError as exc:
        logger.warning(
            "Platform returned non-JSON for cli-exchange: %s",
            exchange.text[:200],
        )
        console.print(
            "  [red]Platform returned an unexpected (non-JSON) response[/] — likely a transient "
            "network or edge issue. Retry shortly or contact us at reporails.com/contact.",
        )
        raise typer.Exit(1) from exc
    except (httpx.HTTPError, OSError) as exc:
        console.print(f"  [red]Failed to exchange token:[/] {exc}")
        raise typer.Exit(1) from exc
    return dict(payload)


@auth_app.command("login")
def login(
    platform_url: str = typer.Option(
        "",
        "--platform-url",
        help="Platform URL (default: https://reporails.com)",
        hidden=True,
    ),
) -> None:
    """Authenticate with GitHub via Device Flow."""
    import httpx

    base_url = platform_url or _get_platform_url()
    try:
        client_id = _resolve_client_id(base_url)
    except SignInRefusedError as exc:
        console.print(f"  [red]{exc}[/]")
        raise typer.Exit(1) from exc
    except PlatformUnavailableError as exc:
        console.print(f"  [red]Reporails platform unavailable:[/] {exc}")
        raise typer.Exit(1) from exc

    if not client_id:
        console.print(
            "  [red]GitHub OAuth not configured on the platform.[/] "
            "The /api/auth/client-id endpoint returned an empty client_id.",
        )
        raise typer.Exit(1)

    # Check if already authenticated
    creds = _read_credentials()
    if creds.get("api_key"):
        console.print(
            f"\n  Already authenticated as [bold]@{creds.get('github_login', '?')}[/]"
            f"{_tier_phrase(creds.get('tier', ''))}.\n"
            "  Run [bold]ails auth logout[/] first to re-authenticate.\n",
        )
        raise typer.Exit(0)

    # Step 1: Request device code from GitHub
    try:
        resp = httpx.post(
            "https://github.com/login/device/code",
            data={"client_id": client_id, "scope": "read:user user:email"},
            headers={"Accept": "application/json", "User-Agent": _user_agent()},
            timeout=10.0,
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, OSError, ValueError) as exc:
        console.print(f"  [red]Failed to start GitHub auth:[/] {exc}")
        raise typer.Exit(1) from exc

    device_code = data["device_code"]
    user_code = data["user_code"]
    interval = data.get("interval", 5)

    console.print(f"\n  Your code: [bold yellow]{user_code}[/]")
    console.print("  Visit:     [link]https://github.com/login/device[/]")
    console.print("  Waiting for authorisation...\n")

    # Step 2: Poll for token
    github_token = _poll_github_token(client_id, device_code, interval)
    if not github_token:
        console.print("  [red]Timed out waiting for authorisation.[/]")
        raise typer.Exit(1)

    # Step 3: Exchange GitHub token for Reporails API key
    payload = _exchange_github_token(base_url, github_token)
    _handle_exchange_response(payload)


def _env_api_key() -> str:
    """Read the `AILS_API_KEY` env override — mirrors api_client.py's env-wins precedence."""
    import os

    return os.environ.get("AILS_API_KEY", "")


# Stored tiers that are safe to echo verbatim — the shared tier vocabulary, not a
# second copy of it. Anything else (empty, or a retired legacy tier string) is
# resolved at check time, so this never prints a stale value.
_DISPLAYABLE_TIERS = ENTITLED_TIERS | UNENTITLED_TIERS
_TIER_UNKNOWN_MSG = "(resolved at check time)"


def _tier_phrase(tier: str) -> str:
    """Render a stored/echoed tier as a trailing ` (<tier> tier)` fragment, or ``.

    The same filter `auth status` applies: only a tier in the shared vocabulary is
    echoed. An unknown or absent tier adds nothing rather than inventing one.
    """
    return f" ({tier} tier)" if tier in _DISPLAYABLE_TIERS else ""


@auth_app.command("status")
def status() -> None:
    """Show current authentication status."""
    env_key = _env_api_key()
    creds = _read_credentials()
    api_key = env_key or creds.get("api_key", "")

    if not api_key:
        console.print("\n  Not authenticated. Run [bold]ails auth login[/] to sign in.\n")
        raise typer.Exit(0)

    # Show prefix only, never the full key
    prefix = api_key[:16] + "..." if len(api_key) > 16 else api_key
    source = "env AILS_API_KEY" if env_key else str(_credentials_path())

    # The stored github_login/tier are only meaningful when the effective key IS the
    # locally cached one — an env-provided key may not match anything on disk at all.
    known_identity = bool(creds.get("api_key")) and creds.get("api_key") == api_key
    stored_tier = creds.get("tier", "") if known_identity else ""
    tier_line = stored_tier if stored_tier in _DISPLAYABLE_TIERS else _TIER_UNKNOWN_MSG

    console.print()
    if known_identity:
        github_login = creds.get("github_login", "?")
        console.print(f"  Authenticated as [bold]@{github_login}[/]")
    else:
        # An env-provided key may not match anything cached on disk, so there
        # is no local github handle to show — and this CLI has no way to look
        # one up for a key it did not issue, so it never will be. Say that
        # plainly instead of `@?` or a promise of a later resolution (only the
        # tier below is genuinely resolved later, by the server, on a check).
        console.print("  Authenticated with an API key [dim](no local identity on record)[/dim]")
    console.print(f"  Tier: [bold]{tier_line}[/]")
    console.print(f"  Key:  {prefix}")
    console.print(f"  Source: {source}\n")


@auth_app.command("logout")
def logout() -> None:
    """Clear stored credentials.

    Only clears the on-disk credentials file — an `AILS_API_KEY` set in the
    environment is a shell/CI concern and is never modified by this command.
    """
    env_key = _env_api_key()
    creds = _read_credentials()

    if not creds.get("api_key"):
        if env_key:
            console.print(
                "\n  No stored credentials to clear. [yellow]AILS_API_KEY[/] is still set "
                "in this shell's environment — unset it separately to fully sign out.\n",
            )
        else:
            console.print("\n  Not authenticated.\n")
        raise typer.Exit(0)

    username = creds.get("github_login", "?")
    _clear_credentials()
    if env_key:
        console.print(
            f"\n  [green]Logged out.[/] Credentials for @{username} removed. "
            "[yellow]AILS_API_KEY[/] is still set in this shell's environment and will "
            "still authenticate ails commands — unset it to fully sign out.\n",
        )
    else:
        console.print(f"\n  [green]Logged out.[/] Credentials for @{username} removed.\n")


@auth_app.command("token")
def token() -> None:
    """Print the effective API key to stdout for use in CI environments.

    Treat this output like a secret — the key is the value to set as
    `AILS_API_KEY` in your CI provider's secret store, or to pass via the
    GitHub Action's `api-key` input. Pipes cleanly:

        AILS_API_KEY=$(ails auth token)
        gh secret set REPORAILS_API_KEY -b "$(ails auth token)"

    Honors an `AILS_API_KEY` env override (env wins over the stored credentials
    file), so it reflects the same key `ails check` would authenticate with.
    Exits non-zero if no key is available from either source, so scripts can
    detect missing credentials.
    """
    env_key = _env_api_key()
    creds = _read_credentials()
    api_key = env_key or creds.get("api_key", "")

    if not api_key:
        console.print("\n  Not authenticated. Run [bold]ails auth login[/] to sign in.\n")
        raise typer.Exit(1)

    # Plain print so the key pipes cleanly without rich formatting.
    print(api_key)
