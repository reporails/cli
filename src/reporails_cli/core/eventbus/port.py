"""The adapter port, the subscriber port and their registries: one adapter per agent turns its payload
into event records, and each subscriber receives every record."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from reporails_cli.core.eventbus.store import append
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.events import EventRecord


class PayloadRefused(Exception):  # noqa: N818  # named for the decision it carries, not a fault
    """The adapter does not know the payload's shape."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class EventAdapter(Protocol):  # pylint: disable=too-few-public-methods  # a port of one method
    """What an agent's adapter offers: its name and the records one payload carries."""

    agent: str

    def resolve(self, payload: JsonObject) -> list[EventRecord]:
        """The records one payload carries; raises `PayloadRefused` on a shape it does not know."""


class EventSubscriber(Protocol):  # pylint: disable=too-few-public-methods  # a port of one method
    """A consumer of event records: called once per record."""

    def __call__(self, record: EventRecord) -> None:
        """Take one record."""


ADAPTERS: dict[str, EventAdapter] = {}
# The store's `append` is the default subscriber.
SUBSCRIBERS: list[EventSubscriber] = [append]


def register(adapter: EventAdapter) -> None:
    """Make `adapter` the one for its agent name."""
    ADAPTERS[adapter.agent] = adapter


def get_adapter(agent: str) -> EventAdapter | None:
    """The adapter registered for `agent`, or None."""
    return ADAPTERS.get(agent)


def subscribe(subscriber: EventSubscriber) -> None:
    """Hand every later record to `subscriber` as well."""
    SUBSCRIBERS.append(subscriber)


def utc_now() -> str:
    """The current time, ISO-8601 UTC."""
    return datetime.now(UTC).isoformat()
