"""The one HTTP GET: a streaming `httpx` client that follows redirects on request."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager

import httpx

from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from reporails_cli.core.platform.contract.http_get import HttpReply

_CHUNK = 1 << 20


class _Reply:
    """A streamed `httpx` response, giving its status, headers and body in pieces."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        self.status = response.status_code

    def header(self, name: str) -> str:
        """The value of response header `name`, or an empty string."""
        return str(self._response.headers.get(name, ""))

    def chunks(self) -> Iterator[bytes]:
        """The body in pieces; a failed transfer raises `PlatformUnavailableError`."""
        try:
            yield from self._response.iter_bytes(_CHUNK)
        except httpx.HTTPError as exc:
            raise PlatformUnavailableError(f"the transfer failed: {exc}") from exc


@contextmanager
def http_get(url: str, *, headers: Mapping[str, str], timeout: float, follow_redirects: bool) -> Iterator[HttpReply]:
    """Open `url`, following redirects when `follow_redirects`, and hold the reply open for the body to be read.

    Raises `PlatformUnavailableError` when the host cannot be reached or the transfer fails.
    """
    try:
        with (
            httpx.Client(timeout=timeout, follow_redirects=follow_redirects, headers=dict(headers)) as client,
            client.stream("GET", url) as response,
        ):
            yield _Reply(response)
    except httpx.HTTPError as exc:
        raise PlatformUnavailableError(f"could not fetch {url}: {exc}") from exc
