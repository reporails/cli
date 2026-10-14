"""The installed reporails-cli version, read once from the package metadata."""

from __future__ import annotations

import functools
from importlib.metadata import PackageNotFoundError, version

UNKNOWN_VERSION = "unknown"


@functools.cache
def installed_version() -> str:
    """The installed package version, or ``"unknown"`` when no package metadata is present."""
    try:
        return version("reporails-cli")
    except PackageNotFoundError:
        return UNKNOWN_VERSION
