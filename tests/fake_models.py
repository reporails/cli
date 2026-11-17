"""A stand-in download port and a model handle built on it: a repair download finds no network."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractContextManager

from reporails_cli.core.mapper.models import Models
from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from reporails_cli.core.platform.contract.http_get import HttpReply


def no_fetch(
    url: str, *, headers: Mapping[str, str], timeout: float, follow_redirects: bool
) -> AbstractContextManager[HttpReply]:
    """A download port with no network: every request fails as an unreachable host does."""
    raise PlatformUnavailableError(f"no network in this test: {url}")


_SHARED = Models(no_fetch)


def no_models() -> Models:
    """The test process's shared model handle, whose repair download has no network (loaded models are reused)."""
    return _SHARED


def fresh_models() -> Models:
    """A new model handle that has loaded nothing, whose repair download has no network."""
    return Models(no_fetch)


def reset_models() -> None:
    """Replace the shared model handle with one that has loaded nothing."""
    global _SHARED  # pylint: disable=global-statement
    _SHARED = Models(no_fetch)
