"""Typed platform faults raised at adapter boundaries.

Pure layer — imports nothing in-project. Adapters raise a `PlatformError`
subtype when a caught fault cannot be honestly collapsed to a guard-clause
sentinel; callers decide whether to degrade (log + continue) or surface it.
"""

from __future__ import annotations


class PlatformError(Exception):
    """Base for a fault caught at a platform adapter boundary."""


class PlatformUnavailableError(PlatformError):
    """An external platform surface was unreachable or returned an unexpected response."""


class PlatformRefusedError(PlatformUnavailableError):
    """The website answered with a non-2xx status; carries the status and the seconds it asked to wait."""

    def __init__(self, message: str, *, status: int, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class CredentialsUnreadableError(PlatformError):
    """The credentials file exists but could not be read or parsed."""


class ConfigUnreadableError(PlatformError):
    """The global config exists but could not be read or parsed."""
