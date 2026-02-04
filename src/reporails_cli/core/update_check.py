"""Check for CLI and framework updates, with 24-hour cache throttling."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from packaging.version import Version

PYPI_URL = "https://pypi.org/pypi/reporails-cli/json"
CACHE_FILE = "update-check.json"
CHECK_INTERVAL_SECONDS = 86400  # 24 hours
REQUEST_TIMEOUT = 5.0


@dataclass(frozen=True)
class UpdateNotification:
    """What's outdated."""

    cli_current: str | None = None
    cli_latest: str | None = None
    rules_current: str | None = None
    rules_latest: str | None = None

    @property
    def has_cli_update(self) -> bool:
        return bool(self.cli_current and self.cli_latest and self.cli_current != self.cli_latest)

    @property
    def has_rules_update(self) -> bool:
        return bool(self.rules_current and self.rules_latest and self.rules_current != self.rules_latest)


def _get_cache_path() -> Path:
    from reporails_cli.core.bootstrap import get_reporails_home

    return get_reporails_home() / "cache" / CACHE_FILE


def _read_cache() -> dict[str, str] | None:
    cache_path = _get_cache_path()
    if not cache_path.exists():
        return None
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        last_checked = datetime.fromisoformat(data["last_checked"])
        elapsed = (datetime.now(UTC) - last_checked).total_seconds()
        if elapsed < CHECK_INTERVAL_SECONDS:
            return dict(data)
    except (json.JSONDecodeError, KeyError, ValueError, OSError):
        pass
    return None


def _write_cache(latest_cli: str | None, latest_rules: str | None) -> None:
    cache_path = _get_cache_path()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "last_checked": datetime.now(UTC).isoformat(),
        "latest_cli_version": latest_cli,
        "latest_rules_version": latest_rules,
    }
    cache_path.write_text(json.dumps(data), encoding="utf-8")


def _fetch_latest_cli_version() -> str | None:
    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            resp = client.get(PYPI_URL)
            resp.raise_for_status()
            version: str | None = resp.json().get("info", {}).get("version")
            return version
    except (httpx.HTTPError, KeyError, ValueError):
        return None


def _is_newer(current: str, latest: str) -> bool:
    """Compare version strings, stripping leading 'v' for packaging.version."""
    try:
        return Version(latest.lstrip("v")) > Version(current.lstrip("v"))
    except Exception:
        return False


def check_for_updates() -> UpdateNotification | None:
    """Check for CLI and framework updates. Returns None if everything is current.

    Reads from cache if checked within 24 hours. Silently returns None on any error.
    """
    try:
        # Try cache first
        cached = _read_cache()
        if cached is not None:
            latest_cli = cached.get("latest_cli_version")
            latest_rules = cached.get("latest_rules_version")
        else:
            # Fetch fresh versions
            from reporails_cli.core.init import get_latest_version

            latest_cli = _fetch_latest_cli_version()
            latest_rules = get_latest_version()
            _write_cache(latest_cli, latest_rules)

        # Compare against installed versions
        from reporails_cli import __version__ as cli_version
        from reporails_cli.core.bootstrap import get_installed_version

        installed_rules = get_installed_version()

        cli_outdated = latest_cli and _is_newer(cli_version, latest_cli)
        rules_outdated = installed_rules and latest_rules and _is_newer(installed_rules, latest_rules)

        if not cli_outdated and not rules_outdated:
            return None

        return UpdateNotification(
            cli_current=cli_version if cli_outdated else None,
            cli_latest=latest_cli if cli_outdated else None,
            rules_current=installed_rules if rules_outdated else None,
            rules_latest=latest_rules if rules_outdated else None,
        )
    except Exception:
        return None


def format_update_message(notification: UpdateNotification) -> str:
    """Format a dim one-liner for Rich console output."""
    parts = []
    if notification.has_cli_update:
        parts.append(f"CLI {notification.cli_current} → {notification.cli_latest}")
    if notification.has_rules_update:
        parts.append(f"framework {notification.rules_current} → {notification.rules_latest}")

    detail = ", ".join(parts)
    commands = []
    if notification.has_cli_update:
        commands.append("ails update --cli")
    if notification.has_rules_update:
        commands.append("ails update")
    cmd = " && ".join(commands)
    return f"[dim]Update available: {detail}. Run: {cmd}[/dim]"
