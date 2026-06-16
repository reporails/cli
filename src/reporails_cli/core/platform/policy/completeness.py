"""Structural-completeness reporting — the per-path gap counts shipped to the server.

Structural/presence rules (mechanical, locally-run) check section / config / file
presence and hygiene. Those rules run client-side — the server never receives file
text — so their per-path error counts ride the request, where the server folds them
into each file's delivery factor — the product of its completeness and truncation
ratios — that scales the score.
The completeness ratio itself is computed server-side (the single scoring authority);
this module only produces the IP-safe per-path map. The rule-id set is supplied by the
caller (resolved from the registry in the adapter layer) so this module stays IO-free.
"""

from __future__ import annotations

from typing import Any


def _is_structural_error(f: Any, structural_ids: frozenset[str]) -> bool:
    """True when `f` is an error-severity finding from the structural family."""
    return getattr(f, "severity", "") == "error" and getattr(f, "rule", "") in structural_ids


def structural_gaps_by_path(findings: Any, structural_ids: frozenset[str]) -> dict[str, int]:
    """Per-path count of structural errors — the IP-safe map sent on the request.

    Structural/presence rules run client-side (the server never sees file text), so
    this count is the only way that signal reaches the api. Counts only — no text,
    no equation values. Keyed by each finding's file path. Only errors count: a missing
    required section / committed credential / broken import is a hard delivery gap;
    warnings (optional sections) do not.
    """
    if not structural_ids:
        return {}
    counts: dict[str, int] = {}
    for f in findings:
        if _is_structural_error(f, structural_ids):
            path = getattr(f, "file", "")
            counts[path] = counts.get(path, 0) + 1
    return counts
