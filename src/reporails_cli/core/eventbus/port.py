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


class TranscriptAdapter(Protocol):
    """What an agent's transcript adapter offers: its name and the records one transcript row carries."""

    agent: str
    # The env var that names the calling session of this agent.
    session_env: str

    def resolve_row(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        """The records one row carries (none for a row type it does not read); raises `PayloadRefused`
        on a row of a known type whose fields do not have the shape it is pinned to."""

    def resolve_subagent(self, subagent_id: str, meta: JsonObject, first_row: JsonObject) -> EventRecord:
        """The `subagent_run` record of one subagent file, from its meta file and its first row; raises
        `PayloadRefused` when either lacks a field it is pinned to."""

    def resolve_brief(self, first_row: JsonObject) -> str:
        """The brief a subagent was given, from the first row of its file; raises `PayloadRefused` when that
        row is not the pinned shape."""

    def holds_call(self, row: JsonObject, use_id: str) -> bool:
        """Whether the row is an assistant row holding the tool call `use_id`."""

    def resolve_prompt(self, row: JsonObject) -> str:
        """The text of a typed prompt, from its row; raises `PayloadRefused` when the row is not one."""

    def resolve_call(self, row: JsonObject, use_id: str) -> str:
        """The shell command of the tool call `use_id`, from its row; raises `PayloadRefused` when the row holds
        no such call or the call has no command."""


class EventSubscriber(Protocol):  # pylint: disable=too-few-public-methods  # a port of one method
    """A consumer of event records: called once per record."""

    def __call__(self, record: EventRecord) -> None:
        """Take one record."""


ADAPTERS: dict[str, EventAdapter] = {}
TRANSCRIPT_ADAPTERS: dict[str, TranscriptAdapter] = {}
# The store's `append` is the default subscriber.
SUBSCRIBERS: list[EventSubscriber] = [append]


def register(adapter: EventAdapter) -> None:
    """Make `adapter` the one for its agent name."""
    ADAPTERS[adapter.agent] = adapter


def get_adapter(agent: str) -> EventAdapter | None:
    """The adapter registered for `agent`, or None."""
    return ADAPTERS.get(agent)


def register_transcript(adapter: TranscriptAdapter) -> None:
    """Make `adapter` the transcript reader for its agent name."""
    TRANSCRIPT_ADAPTERS[adapter.agent] = adapter


def get_transcript_adapter(agent: str) -> TranscriptAdapter | None:
    """The transcript adapter registered for `agent`, or None."""
    return TRANSCRIPT_ADAPTERS.get(agent)


def subscribe(subscriber: EventSubscriber) -> None:
    """Hand every later record to `subscriber` as well."""
    SUBSCRIBERS.append(subscriber)


def utc_now() -> str:
    """The current time, ISO-8601 UTC."""
    return datetime.now(UTC).isoformat()
