"""Rule metadata for text display: docs links, titles and severities.

One cached read of the bundled framework registry feeds every reader here.
"""

from __future__ import annotations

from functools import lru_cache

from reporails_cli.core.platform.adapters.rules_query import load_all_rules, rule_slug, rule_title

_RULE_DOCS_BASE = "https://reporails.com/rules"


@lru_cache(maxsize=1)
def _severities() -> dict[str, str]:
    """`{rule_id: severity}` from the bundled framework registry, loaded once per process."""

    try:
        return {r.id: r.severity.value for r in load_all_rules()}
    except (OSError, ValueError):
        return {}


def rule_severity(rule_id: str) -> str:
    """The registry severity (`critical` .. `low`) of a canonical rule ID, or an empty string when none is known."""
    return _severities().get(rule_id, "")


def rule_docs_url(rule_id: str) -> str | None:
    """Public docs URL (`/rules/<agent|core>/<slug>`) for a canonical rule ID, or None."""
    parts = rule_id.split(":")
    if len(parts) != 3:
        return None
    slug = rule_slug(rule_id)
    if not slug:
        return None
    agent = "core" if parts[0] == "CORE" else parts[0].lower()
    return f"{_RULE_DOCS_BASE}/{agent}/{slug}"


def rule_label(rule_id: str) -> dict[str, str] | None:
    """`{"title": ..., "url": ...}` for a canonical rule ID — a coding agent's label for a
    bare rule code. `url` is omitted when unresolvable; `None` when neither title nor url
    resolves (e.g. an unknown/retired rule ID)."""
    title = rule_title(rule_id)
    url = rule_docs_url(rule_id)
    if not title and not url:
        return None
    entry: dict[str, str] = {}
    if title:
        entry["title"] = title
    if url:
        entry["url"] = url
    return entry


def linked_rule_id(rule: str) -> str:
    """Rule token as a Rich hyperlink to its docs page; plain canonical ID if unresolvable."""
    url = rule_docs_url(rule)
    return f"[link={url}]{rule}[/link]" if url else rule
