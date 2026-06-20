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


# PlatformUnavailableError moved to core.platform.contract.errors; re-exported above
# so the existing `auth_command.PlatformUnavailableError` import path keeps working.
__all__ = ["PlatformUnavailableError"]


# Markers identifying a Cloudflare edge interstitial (managed challenge / JS challenge).
_EDGE_CHALLENGE_MARKERS = (
    "Just a moment",
    "Attention Required! | Cloudflare",
    "challenge-platform",
    "cf-mitigated",
)


def _is_edge_challenge(body: str) -> bool:
    """Detect a Cloudflare edge-challenge interstitial in a response body."""
    return any(marker in body for marker in _EDGE_CHALLENGE_MARKERS)


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
    """Store credentials securely."""
    path = _credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.dump(
            {"api_key": api_key, "github_login": github_login, "tier": tier},
            default_flow_style=False,
        ),
        encoding="utf-8",
    )
    # Restrict permissions to owner only (NTFS ACLs don't support mode bits)
    if sys.platform == "win32":
        logger.warning("File permissions not enforced on Windows — secure %s manually", path)
    else:
        path.chmod(0o600)


def _clear_credentials() -> None:
    """Remove stored credentials."""
    path = _credentials_path()
    if path.exists():
        path.unlink()


def _get_platform_url() -> str:
    """Get platform URL from env or default."""
    import os

    return os.environ.get("AILS_PLATFORM_URL", DEFAULT_PLATFORM_URL).rstrip("/")


def _resolve_client_id(base_url: str) -> str:
    """Resolve the GitHub OAuth client ID, trying embedded constant then platform.

    Raises PlatformUnavailableError when the platform endpoint is reachable but
    returns a non-JSON body (typical of an edge challenge page) — the original
    code silently swallowed this into an empty client_id and surfaced it as a
    misleading "OAuth not configured" message.
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
        if _is_edge_challenge(resp.text):
            raise PlatformUnavailableError(
                "Reporails platform is behind an upstream Cloudflare edge challenge — "
                "this is not fixable in the CLI. Retry shortly or contact support@reporails.com.",
            )
        raise PlatformUnavailableError(
            f"Reporails platform returned HTTP {resp.status_code} for client-id endpoint.",
        )

    try:
        return str(resp.json().get("client_id", ""))
    except ValueError as exc:
        logger.warning("Platform returned non-JSON for client-id: %s", resp.text[:200])
        raise PlatformUnavailableError(
            "Reporails platform returned a non-JSON body for the client-id endpoint — "
            "likely a Cloudflare challenge or proxy error page. Check your network or "
            "contact support@reporails.com.",
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
    """Handle the API key exchange response — waitlist, already enrolled, or success."""
    if payload.get("error") == "waitlist":
        username = payload.get("github_login", "")
        console.print(f"  [yellow]Beta is full.[/] You're on the list, @{username}.")
        console.print("  We'll email you at launch.\n")
        console.print("  [dim]In the meantime: npx ails check . for free diagnostics[/dim]\n")
        raise typer.Exit(0)

    if payload.get("already_enrolled"):
        username = payload.get("github_login", "")
        tier = payload.get("tier", "beta")
        creds = _read_credentials()
        if creds.get("api_key"):
            console.print(f"  Already enrolled as [bold]@{username}[/] ({tier} tier).")
            console.print("  Your existing key is still active.\n")
        else:
            console.print(f"  [yellow]You're enrolled as @{username} ({tier} tier),[/]")
            console.print("  but your local key is missing. Contact support or re-register.\n")
        raise typer.Exit(0)

    api_key = payload.get("api_key")
    if not api_key:
        console.print(f"  [red]Unexpected response from server:[/] {payload}")
        raise typer.Exit(1)

    username = payload.get("github_login", "")
    tier = payload.get("tier", "beta")
    _write_credentials(api_key, username, tier)

    console.print("  [green]Welcome to the beta![/] Full diagnostics unlocked.")
    console.print(f"  Authenticated as [bold]@{username}[/]\n")


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
            f"\n  Already authenticated as [bold]@{creds.get('github_login', '?')}[/] "
            f"({creds.get('tier', 'free').title()} tier).\n"
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
    try:
        exchange = httpx.post(
            f"{base_url}/api/auth/cli-exchange",
            json={"github_token": github_token},
            headers={"Accept": "application/json", "User-Agent": _user_agent()},
            timeout=10.0,
        )
        exchange.raise_for_status()
        payload = exchange.json()
    except ValueError as exc:
        logger.warning(
            "Platform returned non-JSON for cli-exchange: %s",
            exchange.text[:200],
        )
        console.print(
            "  [red]Platform returned a non-JSON response[/] (likely a Cloudflare "
            "challenge page). Contact support@reporails.com.",
        )
        raise typer.Exit(1) from exc
    except (httpx.HTTPError, OSError) as exc:
        if isinstance(exc, httpx.HTTPStatusError) and _is_edge_challenge(exc.response.text):
            console.print(
                "  [red]Upstream Cloudflare edge challenge[/] — not fixable in the CLI. "
                "Retry shortly or contact support@reporails.com.",
            )
            raise typer.Exit(1) from exc
        console.print(f"  [red]Failed to exchange token:[/] {exc}")
        raise typer.Exit(1) from exc

    _handle_exchange_response(payload)


@auth_app.command("status")
def status() -> None:
    """Show current authentication status."""
    creds = _read_credentials()
    if not creds.get("api_key"):
        console.print("\n  Not authenticated. Run [bold]ails auth login[/] to sign in.\n")
        raise typer.Exit(0)

    api_key = creds["api_key"]
    # Show prefix only, never the full key
    prefix = api_key[:16] + "..." if len(api_key) > 16 else api_key

    console.print(f"\n  Authenticated as [bold]@{creds.get('github_login', '?')}[/]")
    console.print(f"  Tier: [bold]{creds.get('tier', '?')}[/]")
    console.print(f"  Key:  {prefix}")
    console.print(f"  File: {_credentials_path()}\n")


@auth_app.command("logout")
def logout() -> None:
    """Clear stored credentials."""
    creds = _read_credentials()
    if not creds.get("api_key"):
        console.print("\n  Not authenticated.\n")
        raise typer.Exit(0)

    username = creds.get("github_login", "?")
    _clear_credentials()
    console.print(f"\n  [green]Logged out.[/] Credentials for @{username} removed.\n")


@auth_app.command("token")
def token() -> None:
    """Print the stored API key to stdout for use in CI environments.

    Treat this output like a secret — the key is the value to set as
    `AILS_API_KEY` in your CI provider's secret store, or to pass via the
    GitHub Action's `api-key` input. Pipes cleanly:

        AILS_API_KEY=$(ails auth token)
        gh secret set REPORAILS_API_KEY -b "$(ails auth token)"

    Exits non-zero if not authenticated, so scripts can detect missing
    credentials.
    """
    creds = _read_credentials()
    if not creds.get("api_key"):
        console.print("\n  Not authenticated. Run [bold]ails auth login[/] to sign in.\n")
        raise typer.Exit(1)

    # Plain print so the key pipes cleanly without rich formatting.
    print(creds["api_key"])
