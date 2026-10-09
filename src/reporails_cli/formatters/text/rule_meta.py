"""Rule metadata for text display: canonical rule IDs, docs links, titles, severities and aliases.

One cached read of the bundled framework registry feeds every reader here.
"""

from __future__ import annotations

from functools import lru_cache
from typing import NamedTuple

from reporails_cli.core.lint.rule_pages import rule_title

# Client-check labels map to their canonical rule ID so local findings display the ID like
# server findings. Unmapped tokens (server IDs, ambiguous_charge) pass through unchanged.
CLIENT_CHECK_RULE_ID = {
    "format": "CORE:E:0003",
    "bold": "CORE:E:0003",
    "heading_instruction": "CORE:S:0039",
}


def display_rule_id(rule: str) -> str:
    """Canonical rule ID for a finding's rule token; unmapped tokens pass through."""
    return CLIENT_CHECK_RULE_ID.get(rule, rule)


_RULE_DOCS_BASE = "https://reporails.com/rules"


class _RuleMeta(NamedTuple):
    """The per-rule registry metadata the docs link, severity and title readers share."""

    slug: str
    severity: str


@lru_cache(maxsize=1)
def _rule_registry() -> dict[str, _RuleMeta]:
    """`{rule_id: _RuleMeta}` from the bundled framework registry, loaded once per process."""
    from reporails_cli.core.platform.adapters.rules_query import load_all_rules

    try:
        return {r.id: _RuleMeta(r.slug or "", r.severity.value) for r in load_all_rules()}
    except (OSError, ValueError):
        return {}


def _rule_slug(rule_id: str) -> str:
    """The registry slug of a rule ID, or an empty string when none is known."""
    meta = _rule_registry().get(rule_id)
    return meta.slug if meta else ""


def rule_severity(rule_id: str) -> str:
    """The registry severity (`critical` .. `low`) of a canonical rule ID, or an empty string when none is known."""
    meta = _rule_registry().get(rule_id)
    return meta.severity if meta else ""


def rule_docs_url(rule_id: str) -> str | None:
    """Public docs URL (`/rules/<agent|core>/<slug>`) for a canonical rule ID, or None."""
    parts = rule_id.split(":")
    if len(parts) != 3:
        return None
    slug = _rule_slug(rule_id)
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
    rule_id = display_rule_id(rule)
    url = rule_docs_url(rule_id)
    return f"[link={url}]{rule_id}[/link]" if url else rule_id


# A rule a suppression directive may also name by its short token, as it has always been written.
SHORT_TOKEN = {"CORE:S:0039": "heading_instruction"}


def rule_aliases(rule: str) -> set[str]:
    """Every name a suppression directive may use for a finding's rule: raw token, canonical ID, slug."""
    canon = display_rule_id(rule)
    names = {rule, canon}
    if canon in SHORT_TOKEN:
        names.add(SHORT_TOKEN[canon])
    slug = _rule_slug(canon)
    if slug:
        names.add(slug)
    return names
