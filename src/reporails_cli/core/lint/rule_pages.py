"""Rule pages (`framework/rules/**/rule.md`) as the user reads them: the Pass / Fail examples, the
description and the public guides, with each section taken from the page's markdown parse."""

from __future__ import annotations

from typing import Literal, get_args

from reporails_cli.core.mapper.structure import section_span
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.models import FileMatch, Rule
from reporails_cli.core.platform.policy.matching import MATCH_PROPERTIES
from reporails_cli.core.platform.utils.utils import read_frontmatter


def _section(text: str, heading: str) -> str | None:
    """Body of the page's `## <heading>` or `### <heading>` section, up to the next heading of the
    same or a higher level; None when the heading is missing or the body is blank."""
    span = section_span(text, heading)
    if span is None:
        return None
    lines = text.split("\n")
    return "\n".join(lines[span[0] : span[1] - 1]).strip() or None


ExampleKind = Literal["pass", "fail"]
EXAMPLE_KINDS: tuple[ExampleKind, ...] = get_args(ExampleKind)


def load_rule_examples(rule: Rule) -> dict[ExampleKind, str | None]:
    """Extract `### Pass` and `### Fail` sections from rule.md body, keyed by example kind."""
    result: dict[ExampleKind, str | None] = dict.fromkeys(EXAMPLE_KINDS)
    if rule.md_path is None or not rule.md_path.exists():
        return result
    try:
        text = rule.md_path.read_text(encoding="utf-8")
    except OSError:
        return result
    for kind in EXAMPLE_KINDS:
        result[kind] = _section(text, kind.capitalize())
    return result


def load_rule_description(rule: Rule) -> str | None:
    """The rule.md body without its frontmatter or its `## Pass / Fail` section.

    The examples render on their own (`load_rule_examples`), so the description stops before
    them rather than printing them twice.
    """
    if rule.md_path is None or not rule.md_path.exists():
        return None
    text = rule.md_path.read_text(encoding="utf-8")
    read = read_frontmatter(text)
    if read.block is None or read.problem is not None:
        return None
    lines = text.split("\n")
    frontmatter_lines = read.block.body_line
    span = section_span(text, "Pass / Fail")
    kept = lines[frontmatter_lines:] if span is None else lines[frontmatter_lines : span[0] - 1] + lines[span[1] - 1 :]
    return "\n".join(kept).strip() or None


def _match_value(value: list[str] | str) -> JsonValue:
    """A match property as it serializes: a string, or a copy of its list."""
    return [*value] if isinstance(value, list) else value


def serialize_match(match: FileMatch | None) -> JsonObject:
    """Serialize FileMatch to dict, including all non-None properties."""
    if match is None:
        return {}
    result: JsonObject = {}
    if match.type is not None:
        result["type"] = _match_value(match.type)
    for prop in MATCH_PROPERTIES:
        val: list[str] | str | None = getattr(match, prop)
        if val is not None:
            result[prop] = _match_value(val)
    return result


def rule_page_summary(rule: Rule) -> JsonObject:
    """A rule's identity and targeting without its description or examples."""
    return {
        "id": rule.id,
        "title": rule.title,
        "slug": rule.slug,
        "category": rule.category.value,
        "severity": rule.severity.value,
        "type": rule.type.value,
        "match": serialize_match(rule.match),
    }


def rule_page_data(rule: Rule) -> JsonObject:
    """A rule page as the explain surfaces show it: metadata, checks, body and Pass / Fail examples."""
    data: JsonObject = {
        "title": rule.title,
        "category": rule.category.value,
        "type": rule.type.value,
        "slug": rule.slug,
        "match": serialize_match(rule.match),
        "severity": rule.severity.value,
        "execution": rule.execution.value,
        "checks": [{"id": c.id, "type": c.type, "severity": (c.severity or rule.severity).value} for c in rule.checks],
        "see_also": [*rule.see_also],
    }
    description = load_rule_description(rule)
    if description:
        data["description"] = description
    data["examples"] = {str(kind): text for kind, text in load_rule_examples(rule).items()}
    return data
