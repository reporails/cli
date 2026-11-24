"""The reply fields of the x-ray page's text routes: what a session's lookup found, shaped for the reply."""

from __future__ import annotations

from collections.abc import Callable

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


def context_fields(session: XraySession, agent: str, name: str) -> JsonObject | None:
    """The reply fields of one item of an agent's own context: its text, and for the system prompt its top-level
    sections with their sizes; an item with no readable text (thinking with signed blocks only) is `unreadable`.
    None for a name that is no item and for an item no recorded request holds."""
    item = next((key for key in OWN_KEYS if key == name), None)
    texts = None if item is None else session.context_text(agent, item)
    if item is None or texts is None:
        return None
    text = _BLOCKS.join(texts)
    if item == "system_prompt":
        return {"text": text, "sections": [section.to_json() for section in top_level_sections(text)]}
    return {"text": text, "unreadable": not texts}


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
