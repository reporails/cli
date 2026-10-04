"""Per-project scan analytics data shapes.

Pure data models for a project's scan history. Persistence and identification
logic live in the observability layer; these shapes are shared by that layer,
the cache, and the scan-delta computation in `dto.results`.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AnalyticsEntry:
    """Single analytics entry for a project scan."""

    timestamp: str
    score: float
    level: str
    violations_count: int
    rules_checked: int
    elapsed_ms: float
    instruction_files: int


@dataclass
class ProjectAnalytics:
    """Analytics for a single project."""

    project_id: str
    project_name: str
    project_path: str
    first_seen: str
    last_seen: str
    scan_count: int = 0
    history: list[AnalyticsEntry] = field(default_factory=list)
