"""The reply fields of the x-ray page's text routes: what a session's lookup found, shaped for the reply."""

from __future__ import annotations

import math
from collections.abc import Callable

from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.mapper.structure import top_level_sections
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.diagnostics import FindingItem
from reporails_cli.core.platform.dto.xray_own import OWN_KEYS
from reporails_cli.core.platform.rules.registry import file_level_check_ids
from reporails_cli.core.platform.rules.rules_query import rule_category, rule_title
from reporails_cli.core.xray.session import XraySession
from reporails_cli.formatters.text.rule_meta import rule_docs_url

# What joins the blocks of one item's text.
_BLOCKS = "\n\n"


def text_fields(lookup: Callable[[XraySession, str], str | None]) -> Callable[[XraySession, str], JsonObject | None]:
    """A lookup that finds a text, as one that finds the reply's `text` field."""

    def fields(session: XraySession, key: str) -> JsonObject | None:
        text = lookup(session, key)
        return None if text is None else {"text": text}

    return fields


def seconds_of(text: str) -> float | None:
    """The number of seconds a query value writes; None for text that is no finite number."""
    try:
        seconds = float(text)
    except ValueError:
        return None
    return seconds if math.isfinite(seconds) else None


def in_context_fields(session: XraySession, agent: str, at: str) -> JsonObject | None:
    """The reply fields of an agent's "in context" list at its last reply at or before `at` seconds into the
    session; None for an agent the session lists none of and a moment before the agent's first reply. Raises
    `PayloadRefused` naming `at` when it is no number of seconds, 0 or more."""
    moment = seconds_of(at)
    if moment is None or moment < 0:
        raise PayloadRefused("at is not a number of seconds, 0 or more")
    found = session.in_context_at(agent, moment)
    return None if found is None else found.to_json()


def context_fields(session: XraySession, agent: str, name: str) -> JsonObject | None:
    """The reply fields of one item of an agent's own context: its text, and for the system prompt its top-level
    sections with their sizes; an item with no readable text (thinking with signed blocks only) is `unreadable`.
    None for a name that is no item and for an item no recorded request holds."""
    item = next((key for key in OWN_KEYS if key == name), None)
    texts = None if item is None else session.context_text(agent, item)
    row = None if item is None else session.own_item(agent, item)
    if item is None or texts is None or row is None:
        return None
    text = _BLOCKS.join(texts)
    if item == "system_prompt":
        sections = top_level_sections(text)
        total = sum(section.chars for section in sections)
        return {
            "text": text,
            "sections": [
                {**section.to_json(), "tokens": round(row.tokens_est * section.chars / total) if total else 0}
                for section in sections
            ],
        }
    fields: JsonObject = {"text": text, "unreadable": not texts}
    if row.unread is not None and row.measure is not None:
        fields |= {"readable": sum(len(part) for part in texts), "counted": row.measure.chars, "unread": row.unread}
    return fields


def hook_output_fields(session: XraySession, key: str) -> JsonObject | None:
    """The reply fields of a hook firing the session names: its output and whether the output was cut."""
    found = session.hook_output(key)
    return None if found is None else {"text": found[0], "truncated": found[1]}


def call_fields(session: XraySession, key: str) -> JsonObject | None:
    """The reply fields of a call the session names: its tool, command, input and result excerpt."""
    detail = session.call(key)
    if detail is None:
        return None
    return {
        "tool": detail.tool,
        "text": detail.text,
        "input": detail.input,
        "result": detail.result,
        "truncated": detail.truncated,
    }


def finding_fields(finding: FindingItem) -> JsonObject:
    """One finding as the page shows it."""
    return {
        "line": finding.line,
        "rule": finding.rule,
        "message": finding.message,
        "severity": finding.severity,
        "title": rule_title(finding.rule),
        "category": rule_category(finding.rule),
        "file_level": finding.check_id in file_level_check_ids() or finding.line == 0,
        "docs_url": rule_docs_url(finding.rule),
    }
