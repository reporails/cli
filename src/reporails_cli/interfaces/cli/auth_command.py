"""ails auth — authenticate with the Reporails platform.

Supports GitHub Device Flow for terminal-based authentication.
The API key is stored in ~/.reporails/credentials.yml (not in the project).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import typer
import yaml
from rich.console import Console

logger = logging.getLogger(__name__)

console = Console(emoji=False, highlight=False)
auth_app = typer.Typer(
    name="auth",
    help="Authenticate with the Reporails platform.",
    no_args_is_help=True,
)

# GitHub OAuth App Client ID — public, embedded in CLI.
# This is NOT a secret. GitHub Device Flow requires the client ID
# to be available client-side.
GITHUB_CLIENT_ID = ""  # Set when GitHub OAuth App is created

# Reporails platform URL — configurable for local dev
DEFAULT_PLATFORM_URL = "https://reporails.com"


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
    # Restrict permissions to owner only
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
    """Resolve the GitHub OAuth client ID, trying embedded constant then platform."""
    import httpx

    client_id = GITHUB_CLIENT_ID
    if not client_id:
        try:
            resp = httpx.get(f"{base_url}/api/auth/client-id", timeout=5.0)
            resp.raise_for_status()
            client_id = resp.json().get("client_id", "")
        except (httpx.HTTPError, OSError, ValueError):
            pass
    return client_id


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
                headers={"Accept": "application/json"},
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
    client_id = _resolve_client_id(base_url)

    if not client_id:
        console.print(
            "  [red]GitHub OAuth not configured.[/] Set GITHUB_CLIENT_ID in the CLI or configure the platform.",
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
            headers={"Accept": "application/json"},
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
            timeout=10.0,
        )
        exchange.raise_for_status()
        payload = exchange.json()
    except (httpx.HTTPError, OSError, ValueError) as exc:
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
