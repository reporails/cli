"""An HTTP GET, as a typed contract."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager
from typing import Protocol


class HttpReply(Protocol):
    """The answer to a GET: its status, its headers and its body in pieces."""

    status: int

    def header(self, name: str) -> str:
        """The value of response header `name`, or an empty string when the reply has none."""

    def chunks(self) -> Iterator[bytes]:
        """The body, streamed in pieces."""


class HttpGet(Protocol):  # pylint: disable=too-few-public-methods  # a callable, not a class with methods
    """Fetches a URL and holds the reply open for the caller to read; the caller says whether redirects are followed."""

    def __call__(
        self, url: str, *, headers: Mapping[str, str], timeout: float, follow_redirects: bool
    ) -> AbstractContextManager[HttpReply]:
        """Open `url` with `headers`, giving up after `timeout` seconds, following redirects when `follow_redirects`
        (otherwise a redirect is the reply). Raises `PlatformUnavailableError` when the
        host cannot be reached or the transfer fails."""
