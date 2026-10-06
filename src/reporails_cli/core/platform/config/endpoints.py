"""Where the website lives: the sign-in address, from the environment or the default."""

from __future__ import annotations

import os

DEFAULT_PLATFORM_URL = "https://reporails.com"


def platform_url() -> str:
    """The website address without a trailing slash: `AILS_PLATFORM_URL` when set, else the default."""
    return os.environ.get("AILS_PLATFORM_URL", "").strip().rstrip("/") or DEFAULT_PLATFORM_URL
