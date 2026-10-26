"""Where the website and the diagnostics server live, from the environment or the defaults."""

from __future__ import annotations

from reporails_cli.core.platform.config.bootstrap import env_text

DEFAULT_PLATFORM_URL = "https://reporails.com"
# The diagnostics server used when `AILS_SERVER_URL` is unset.
DEFAULT_SERVER_URL = "https://api.reporails.com"


def _address(var_name: str, default: str) -> str:
    """The env var's address stripped of spaces and a trailing slash, else *default*."""
    return env_text(var_name).rstrip("/") or default


def platform_url() -> str:
    """The website address without a trailing slash: `AILS_PLATFORM_URL` when set, else the default."""
    return _address("AILS_PLATFORM_URL", DEFAULT_PLATFORM_URL)


def server_url() -> str:
    """The diagnostics server address without a trailing slash: `AILS_SERVER_URL` when set, else the default."""
    return _address("AILS_SERVER_URL", DEFAULT_SERVER_URL)
