"""Rule pages (`framework/rules/**/rule.md`) as the user reads them: the Pass / Fail examples, the
description and the public guides, with each section taken from the page's markdown parse."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.mapper.structure import section_span
from reporails_cli.core.platform.adapters.registry import infer_agent_from_rule_id
from reporails_cli.core.platform.adapters.rules_query import load_all_rules
from reporails_cli.core.platform.dto.models import Rule
from reporails_cli.core.platform.utils.utils import frontmatter_block, read_frontmatter


def _section(text: str, heading: str) -> str | None:
    """Body of the page's `## <heading>` or `### <heading>` section, up to the next heading of the
    same or a higher level; None when the heading is missing or the body is blank."""
    span = section_span(text, heading)
    if span is None:
        return None
    lines = text.split("\n")
    return "\n".join(lines[span[0] : span[1] - 1]).strip() or None


def load_rule_examples(rule: Rule) -> dict[str, str | None]:
    """Extract `### Pass` and `### Fail` sections from rule.md body."""
    result: dict[str, str | None] = {"pass": None, "fail": None}
    if rule.md_path is None or not rule.md_path.exists():
        return result
    try:
        text = rule.md_path.read_text(encoding="utf-8")
    except OSError:
        return result
    result["pass"] = _section(text, "Pass")
    result["fail"] = _section(text, "Fail")
    return result


def load_rule_guides(rule_ids: list[str], rules_dir: Path | None = None) -> dict[str, dict[str, str]]:
    """Each named rule's public guide — its title, Pass example and antipatterns — once per rule,
    in first-named order. An id no rule file declares is left out, and so is a missing or
    unreadable section."""
    ids = list(dict.fromkeys(rule_ids))
    agents = sorted({agent for agent in map(infer_agent_from_rule_id, ids) if agent})
    by_id = {rule.id: rule for rule in load_all_rules(agents, rules_dir)}
    guides: dict[str, dict[str, str]] = {}
    for rule_id in ids:
        rule = by_id.get(rule_id)
        if rule is None:
            continue
        guide = {"title": rule.title}
        try:
            text = rule.md_path.read_text(encoding="utf-8") if rule.md_path is not None else ""
        except OSError:
            text = ""
        for key, heading in (("pass", "Pass"), ("antipatterns", "Antipatterns")):
            section = _section(text, heading)
            if section:
                guide[key] = section
        guides[rule_id] = guide
    return guides


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
    frontmatter_lines = frontmatter_block(text).body_line  # type: ignore[union-attr]
    span = section_span(text, "Pass / Fail")
    kept = lines[frontmatter_lines:] if span is None else lines[frontmatter_lines : span[0] - 1] + lines[span[1] - 1 :]
    return "\n".join(kept).strip() or None
