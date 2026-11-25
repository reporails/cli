"""The adapter port, the subscriber port and their registries: one adapter per agent turns its payload
into event records, and each subscriber receives every record."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar, Protocol

from reporails_cli.core.eventbus.store import append
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.events import (
    EventRecord,
    HarnessKind,
    MessageText,
    RequestChain,
)
from reporails_cli.core.platform.dto.workflows import WorkflowRun


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


# The text of one entry of a listing under the name it is listed by; None for a listing that names none.
ListingPieces = tuple[tuple[str | None, str], ...]


class ContextReader(Protocol):
    """Reads the text an attachment row puts into the agent's own context."""

    def resolve_listing_text(self, row: JsonObject) -> tuple[HarnessKind, ListingPieces] | None:
        """The kind and the pieces of text, each under its name, of an attachment row the size of the agent's own
        context counts as a listing; None for any other row. Raises `PayloadRefused` for a pinned field of another
        shape."""

    def resolve_note_body(self, text: str) -> str:
        """The text of a note without the wrapper the agent puts around the notes it injects."""

    def resolve_claimed(self, row: JsonObject) -> list[str]:
        """The texts an attachment row puts into the context that a row other than the other messages counts: a
        hook's note, an instruction file's content, a listing. Empty for any other row."""


class TranscriptAdapter(Protocol):
    """What an agent's transcript adapter offers: its name and the records one transcript row carries."""

    agent: str
    # The env var that names the calling session of this agent.
    session_env: str
    # Reads the text its attachment rows put into the agent's own context.
    context: ClassVar[ContextReader]

    def resolve_row(
        self, row: JsonObject, subagent_id: str | None, requests: RequestChain | None = None
    ) -> list[EventRecord]:
        """The records one row carries (none for a row type it does not read); with `requests`, the row is also fed
        to that chain and a request row yields its sized request; raises `PayloadRefused`
        on a row of a known type whose fields do not have the shape it is pinned to."""

    def resolve_subagent(
        self, subagent_id: str, meta: JsonObject, first_row: JsonObject, workflow_run: str | None = None
    ) -> EventRecord:
        """The `subagent_run` record of one subagent file, from its meta file and its first row; for an agent of a
        workflow run, the run's id; raises `PayloadRefused` when either lacks a field it is pinned to."""

    def resolve_workflow_run(
        self, run_id: str, record: JsonObject | None, journal: list[JsonObject], metas: dict[str, JsonObject]
    ) -> WorkflowRun:
        """The workflow run `run_id`, from its record file; with no record file (`record` None), from the journal
        rows and the meta files of its agents, as a running run, each agent with the size of the output the run
        accepted from it. Raises `PayloadRefused` when a record or a journal row is not the pinned shape."""

    def resolve_brief(self, first_row: JsonObject) -> str:
        """The brief a subagent was given, from the first row of its file; raises `PayloadRefused` when that
        row is not the pinned shape."""

    def resolve_handback(self, row: JsonObject, agent_id: str) -> str | None:
        """What the row says agent `agent_id` handed back: the message of a hand-back call it holds, or the output a
        workflow run's journal row says the run accepted from that agent; None for any other row. Raises
        `PayloadRefused` when the call or the journal row is not the pinned shape."""

    def resolve_reply(self, row: JsonObject) -> str | None:
        """The text of an assistant reply row; None for any other row or a row with no text. Raises `PayloadRefused` for
        a text block with no text."""

    def resolve_request(self, row: JsonObject) -> tuple[str, str] | None:
        """The id and the request shape hash of an API request row; None for any other row; raises `PayloadRefused`
        when the row's hash is not the pinned shape."""

    def resolve_shape_text(self, row: JsonObject, shape_hash: str, item: str) -> str | None:
        """The text of own-context item `item` (the system prompt or the tool definitions) in the request-shape row
        recorded under `shape_hash`; None for any other row or item; raises `PayloadRefused` when that row is not
        the pinned shape."""

    def request_blocks(self, chain: RequestChain) -> list[MessageText]:
        """The notes and thinking of the messages of the request `chain` last took, in message order."""

    def holds_call(self, row: JsonObject, use_id: str) -> bool:
        """Whether the row is an assistant row holding the tool call `use_id`."""

    def resolve_prompt(self, row: JsonObject) -> str:
        """The text of a typed prompt, from its row; raises `PayloadRefused` when the row is not one."""

    def resolve_compact_summary(self, row: JsonObject) -> str | None:
        """The summary text of a compaction summary row; None for any other row."""

    def resolve_compact_link(self, row: JsonObject) -> str | None:
        """The id of the compaction boundary row a compaction summary row follows; None for any other row or a
        summary row that names none."""

    def opens_with_clear(self, row: JsonObject) -> bool | None:
        """For the row that opens a session's conversation, whether it is the agent's `/clear` command; None for a
        row that does not open it."""

    def row_time(self, row: JsonObject) -> str | None:
        """The time the row was written; None for a row that records none."""

    def resolve_hook_output(self, row: JsonObject) -> str:
        """The text a hook row holds, from its row; raises `PayloadRefused` when the row is not a hook row."""

    def resolve_call(self, row: JsonObject, use_id: str) -> str:
        """The shell command of the tool call `use_id`, from its row; raises `PayloadRefused` when the row holds
        no such call or the call has no command."""

    def resolve_call_input(self, row: JsonObject, use_id: str) -> JsonObject:
        """The input of the tool call `use_id`, from its row; raises `PayloadRefused` when the row holds no such
        call."""

    def holds_result(self, row: JsonObject, use_id: str) -> bool:
        """Whether the row holds the result of the tool call `use_id`."""

    def resolve_result(self, row: JsonObject, use_id: str) -> str:
        """The text of the result of the tool call `use_id`, from its row; raises `PayloadRefused` when the row
        holds no such result or its content is neither text nor a list of blocks."""


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
