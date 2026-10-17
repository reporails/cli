"""Helpers for the ``ails explain`` command."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.platform.adapters.rules_query import load_all_rules


def _explain_rules_paths(rules: list[str] | None) -> list[Path] | None:
    """Resolve rules paths for explain command."""
    if rules:
        return [Path(r).resolve() for r in rules]
    return None


def _resolve_rule_token(token: str) -> str:
    """Map either a rule ID or a rule slug to a canonical ID."""
    if ":" in token:
        return token.upper()

    for rule in load_all_rules():
        if rule.slug == token:
            return rule.id
    return token
