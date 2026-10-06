"""Mechanical-check result data shape.

Pure data returned by a single mechanical check. Shared by the lint mechanical
runner (which produces it) and the per-run check cache (which stores it),
without either reaching into the other.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CheckResult:
    """Result of a single mechanical check."""

    passed: bool
    message: str
    annotations: dict[str, Any] | None = None  # D->M metadata (e.g., discovered_imports)
    location: str | None = None  # Per-file location override (e.g., "SKILL.md:0")
    # One (location, message) per failing occurrence (e.g. each broken link on its own line);
    # when set, a failed check reports each occurrence instead of one aggregate finding.
    occurrences: list[tuple[str, str]] | None = None
