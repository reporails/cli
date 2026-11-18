"""A stand-in `DaemonTransport`: answers each request from a canned reply or a function, no socket."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from reporails_cli.core.platform.contract.json_value import JsonObject

Answer = Callable[[JsonObject, Callable[[JsonObject], None] | None], JsonObject]


class FakeDaemonTransport:
    """Records every exchange; answers with `reply`, or with `answer(request, on_message)` when given.

    With neither, the socket does not answer: `exchange` raises `PlatformUnavailableError`.
    """

    def __init__(self, reply: JsonObject | None = None, *, answer: Answer | None = None) -> None:
        self.reply = reply
        self.answer = answer
        self.exchanges: list[tuple[Path, JsonObject]] = []

    def exchange(
        self,
        address: Path,
        request: JsonObject,
        *,
        timeout: float,
        on_message: Callable[[JsonObject], None] | None,
    ) -> JsonObject:
        self.exchanges.append((address, request))
        if self.answer is not None:
            return self.answer(request, on_message)
        if self.reply is None:
            raise PlatformUnavailableError("the fake daemon does not answer")
        return self.reply

    def serve(
        self,
        address: Path,
        handle: Callable[[JsonObject, Callable[[JsonObject], None]], JsonObject],
        *,
        idle_timeout: int | None,
    ) -> None:
        raise AssertionError("a fake transport does not serve")
