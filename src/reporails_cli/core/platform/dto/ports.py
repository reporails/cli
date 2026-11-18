"""The calls a core function makes out to the server, as typed contracts a caller supplies."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.diagnostics import LintResponse, Notice
from reporails_cli.core.platform.dto.models import LocalEntry
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.dto.sign_in import Handshake, Surface

# Asks the server whether it serves a caller on `Surface`: its verdict, or why there is none.
Handshaker = Callable[[Surface], Handshake]


class LintService(Protocol):
    """The server lint of one run's local findings, and the notices a user is shown."""

    def lint(
        self,
        ruleset_map: RulesetMap,
        local: Sequence[LocalEntry],
        structural_required: int,
        *,
        root: Path,
    ) -> LintResponse:
        """The server's reply to `ruleset_map` and the reported `local` findings, paths relative to `root`."""

    def visible_notices(self, notices: tuple[Notice, ...]) -> tuple[Notice, ...]:
        """`notices` without the ones a user opted out of seeing."""


class DaemonTransport(Protocol):
    """The socket the mapper daemon is reached on: the bytes on it, not the commands that travel over it."""

    def exchange(
        self,
        address: Path,
        request: JsonObject,
        *,
        timeout: float,
        on_message: Callable[[JsonObject], None] | None,
    ) -> JsonObject:
        """Send `request` to the socket at `address` and read the frames the daemon streams back.

        A frame carrying `"type": "progress"` goes to `on_message` (when given) and reading continues; the first
        other frame is the reply and is returned. Raises `PlatformUnavailableError` when the socket does not
        answer: absent, refusing, timed out, closed before a reply, or a frame that is not a JSON object.
        """

    def serve(
        self,
        address: Path,
        handle: Callable[[JsonObject, Callable[[JsonObject], None]], JsonObject],
        *,
        idle_timeout: int | None,
    ) -> None:
        """Bind the socket at `address` and answer each connection's request with `handle(request, send)`.

        `send` writes one more frame to the connection before the reply. Connections are served one at a time.
        Returns on SIGTERM or SIGINT, or after `idle_timeout` seconds without a connection (`None`: never).
        """
