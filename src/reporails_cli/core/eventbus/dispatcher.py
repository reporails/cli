"""Turn one raw hook payload into records in the session log. Never raises."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from reporails_cli.core.eventbus import store
from reporails_cli.core.eventbus.adapters.claude import ClaudeAdapter
from reporails_cli.core.eventbus.port import SUBSCRIBERS, PayloadRefused, get_adapter, register, utc_now
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object, as_str
from reporails_cli.core.platform.dto.events import EventRecord

logger = logging.getLogger(__name__)

register(ClaudeAdapter())


def record_payload(agent: str, raw: bytes | str) -> None:
    """Append the records the agent's adapter resolves from `raw`, or one `refusal` record. Never raises."""
    try:
        _record(agent, raw)
    except Exception:  # pylint: disable=broad-exception-caught  # the hook must never fail the agent
        logger.debug("event bus could not record a payload", exc_info=True)


def _deliver(record: EventRecord) -> None:
    for subscriber in SUBSCRIBERS:
        try:
            subscriber(record)
        except Exception:  # pylint: disable=broad-exception-caught  # one subscriber must not stop the others
            logger.debug("event subscriber failed", exc_info=True)


def _record(agent: str, raw: bytes | str) -> None:
    payload: JsonObject = {}
    try:
        payload = as_object(json.loads(raw))
        adapter = get_adapter(agent)
        if adapter is None:
            raise PayloadRefused(f"unknown agent: {agent}")
        records = adapter.resolve(payload)
    except (ValueError, PayloadRefused) as err:
        reason = err.reason if isinstance(err, PayloadRefused) else f"payload is not JSON: {err}"
        records = [
            EventRecord(
                agent=agent,
                event="refusal",
                session_id=as_str(payload.get("session_id")) or "unknown",
                time=utc_now(),
                refusal=reason,
            )
        ]
    for record in records:
        _deliver(record)
        if record.event == "session_start":
            store.prune(None if record.cwd is None else Path(record.cwd))
