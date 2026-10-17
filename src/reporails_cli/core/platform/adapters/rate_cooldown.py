"""Local rate-limit cooldown — hold off the diagnostics call while a 429 window is open.

A `rate_limit_exceeded` response carries `reset_in`. The window end is persisted
in `~/.reporails/rate_limit.json` so every run inside that window returns the same
rate-limit error without a round-trip, with `reset_in` counted down to the
remaining seconds. Entries are keyed by endpoint + credential, so signing in,
switching keys, or pointing at another server starts clean. A signed-in user on
a free plan is never held: upgrading keeps the same key, so the next run asks the
server, which refuses again while the user is still on the free plan and serves
the run once they are on a paid one.

Every failure here (unreadable, corrupt, or unwritable file) degrades to "no
cooldown" — the worst case is one extra request, never a blocked run.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

from reporails_cli.core.platform.config.bootstrap import get_reporails_home
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_int, as_object, as_str
from reporails_cli.core.platform.dto.diagnostics import UNENTITLED_TIERS, FunnelError
from reporails_cli.core.platform.utils.utils import write_json_atomic

logger = logging.getLogger(__name__)

RATE_LIMIT_ERROR = "rate_limit_exceeded"

# Never hold a cooldown longer than this, whatever `reset_in` claims — a bogus
# value must not lock a user out for days.
MAX_COOLDOWN_SECONDS = 3600


def _cooldown_path() -> Path:
    # Kept outside the cache directory: that directory may be restored onto a
    # different machine (CI caches it), and a cooldown belongs to the machine
    # that received the rate-limit response.
    return get_reporails_home() / "rate_limit.json"


def _principal_key(base_url: str, api_key: str) -> str:
    """Opaque per-endpoint, per-credential key; the raw API key is never stored."""
    return hashlib.sha256(f"{base_url.rstrip('/')}\0{api_key}".encode()).hexdigest()[:32]


def _load() -> JsonObject:
    try:
        data: JsonValue = json.loads(_cooldown_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        logger.debug("Ignoring unreadable rate-limit cooldown file: %s", exc)
        return {}
    return as_object(data)


def _save(entries: JsonObject) -> None:
    try:
        write_json_atomic(_cooldown_path(), entries)
    except OSError as exc:
        logger.debug("Could not persist rate-limit cooldown: %s", exc)


def _window_open(entry: JsonValue, now: float) -> bool:
    """True when `entry` is a stored cooldown whose window ends after `now`."""
    if not isinstance(entry, dict):
        return False
    until = entry.get("until")
    return isinstance(until, (int, float)) and until > now


def active_cooldown(base_url: str, api_key: str) -> FunnelError | None:
    """Return the stored rate-limit error while its window is still open, else None."""
    entry = _load().get(_principal_key(base_url, api_key))
    if not isinstance(entry, dict):
        return None
    until = entry.get("until")
    if not isinstance(until, (int, float, str)):
        return None
    try:
        remaining = int(float(until) - time.time())
    except ValueError:
        return None
    if remaining <= 0:
        return None
    tier = as_str(entry.get("tier", ""))
    if api_key and tier in UNENTITLED_TIERS:
        return None
    return FunnelError(
        error=RATE_LIMIT_ERROR,
        tier=tier,
        limit=as_int(entry.get("limit"), 0),
        reset_in=min(remaining, MAX_COOLDOWN_SECONDS),
        upgrade_url=as_str(entry.get("upgrade_url", "")),
        message=as_str(entry.get("message", "")),
        status=429,
    )


def record_cooldown(base_url: str, api_key: str, err: FunnelError) -> None:
    """Persist a rate-limit error's window; a no-op for any other error or a missing `reset_in`."""
    if err.error != RATE_LIMIT_ERROR or err.reset_in <= 0:
        return
    if api_key and err.tier in UNENTITLED_TIERS:
        return  # never read back: a keyed free user is not held
    now = time.time()
    entries = {key: entry for key, entry in _load().items() if _window_open(entry, now)}
    entries[_principal_key(base_url, api_key)] = {
        "until": now + min(err.reset_in, MAX_COOLDOWN_SECONDS),
        "tier": err.tier,
        "limit": err.limit,
        "upgrade_url": err.upgrade_url,
        "message": err.message,
    }
    _save(entries)
