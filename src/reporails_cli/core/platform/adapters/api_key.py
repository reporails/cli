"""Which API key and server a request uses: no network code, so any layer may read it."""

from __future__ import annotations

import logging
from collections.abc import Callable

from reporails_cli.core.platform.config.credentials import env_api_key, load_credentials_record
from reporails_cli.core.platform.config.endpoints import DEFAULT_SERVER_URL, server_url
from reporails_cli.core.platform.contract.errors import PlatformError

logger = logging.getLogger(__name__)


def api_key_from_credentials() -> str:
    """Read API key from ~/.reporails/credentials.yml (set by `ails login`).

    Returns "" only for genuine absence (no file / no key). Raises
    CredentialsUnreadableError when the file exists but cannot be read or parsed.
    """
    return str(load_credentials_record().get("api_key") or "")


def degrade_on_fault(reader: Callable[[], str], unit: str) -> str:
    """Run a credentials/config read; on PlatformError drop the unit with a visible WARNING.

    The legitimate crash-firewall: a corrupt file surfaces as a WARNING and the
    session continues anonymous, rather than crashing or being debug-buried.
    """
    try:
        return reader()
    except PlatformError as exc:
        logger.warning("Dropping %s and continuing anonymous: %s", unit, exc)
        return ""


def resolve_api_key() -> str:
    """The API key in effect: ``AILS_API_KEY`` when set, else the stored credentials.

    Returns "" when neither holds a key; an unreadable credentials file drops
    to "" with a WARNING.
    """
    return env_api_key() or degrade_on_fault(api_key_from_credentials, "API key")


def default_server_api_key() -> str:
    """The API key in effect when ``AILS_SERVER_URL`` is unset or the default server, else "".

    A key paired with another server (a local or staging one) is not returned.
    """
    if server_url() != DEFAULT_SERVER_URL:
        return ""
    return resolve_api_key()


def has_api_key() -> bool:
    """True when an API key is available (env override or stored credentials).

    Client-side affordance gate: distinguishes an authenticated user from an
    anonymous one without consulting the server. This only gates which local
    affordances are offered; the plan itself is whatever the server reports.
    """
    return bool(resolve_api_key())
