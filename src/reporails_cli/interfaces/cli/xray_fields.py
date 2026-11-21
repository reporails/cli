"""The reply fields of the x-ray page's text routes: what a session's lookup found, shaped for the reply."""

from __future__ import annotations

from collections.abc import Callable

from reporails_cli.core.mapper.structure import top_level_sections
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.xray.session import XraySession


def text_fields(lookup: Callable[[XraySession, str], str | None]) -> Callable[[XraySession, str], JsonObject | None]:
    """A lookup that finds a text, as one that finds the reply's `text` field."""

    def fields(session: XraySession, key: str) -> JsonObject | None:
        text = lookup(session, key)
        return None if text is None else {"text": text}

    return fields


def system_fields(session: XraySession, agent_type: str) -> JsonObject | None:
    """The reply fields of a system prompt the session names: its text and its top-level sections with their sizes."""
    text = session.system_prompt(agent_type)
    if text is None:
        return None
    return {"text": text, "sections": [section.to_json() for section in top_level_sections(text)]}


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
