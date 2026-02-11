"""Global analytics - per-project scan history and trend tracking.

Global (~/.reporails/analytics/):
  - projects/{hash}.json  # Per-project analytics
  - aggregated.json       # Cross-project insights (future)
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from reporails_cli.core.bootstrap import get_reporails_home


def get_analytics_dir() -> Path:
    """Get global analytics directory."""
    return get_reporails_home() / "analytics" / "projects"


# =============================================================================
# Project Identification
# =============================================================================


def get_git_remote(target: Path) -> str | None:
    """Get git remote URL for project identification."""
    try:
        result = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=target,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def get_project_id(target: Path) -> str:
    """
    Get unique project identifier.

    Uses git remote URL hash for consistency across clones,
    falls back to absolute path hash.

    Args:
        target: Project root

    Returns:
        12-character hex hash
    """
    # Try git remote first (consistent across clones), fallback to absolute path
    remote = get_git_remote(target)
    source = remote or str(target.resolve())

    return hashlib.sha256(source.encode()).hexdigest()[:12]


def get_project_name(target: Path) -> str:
    """Get human-readable project name."""
    return target.resolve().name


# =============================================================================
# Analytics Data Models
# =============================================================================


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


# =============================================================================
# Analytics Persistence
# =============================================================================


def get_project_analytics_path(project_id: str) -> Path:
    """Get path to project's analytics file."""
    return get_analytics_dir() / f"{project_id}.json"


def load_project_analytics(project_id: str) -> ProjectAnalytics | None:
    """Load analytics for a project."""
    path = get_project_analytics_path(project_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return ProjectAnalytics(
            project_id=data["project_id"],
            project_name=data["project_name"],
            project_path=data["project_path"],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            scan_count=data.get("scan_count", 0),
            history=[AnalyticsEntry(**entry) for entry in data.get("history", [])],
        )
    except (json.JSONDecodeError, KeyError, OSError):
        return None


def save_project_analytics(analytics: ProjectAnalytics) -> None:
    """Save project analytics."""
    path = get_project_analytics_path(analytics.project_id)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "project_id": analytics.project_id,
        "project_name": analytics.project_name,
        "project_path": analytics.project_path,
        "first_seen": analytics.first_seen,
        "last_seen": analytics.last_seen,
        "scan_count": analytics.scan_count,
        "history": [
            {
                "timestamp": e.timestamp,
                "score": e.score,
                "level": e.level,
                "violations_count": e.violations_count,
                "rules_checked": e.rules_checked,
                "elapsed_ms": e.elapsed_ms,
                "instruction_files": e.instruction_files,
            }
            for e in analytics.history
        ],
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def get_previous_scan(target: Path) -> AnalyticsEntry | None:
    """Get the most recent scan entry for comparison (before current run is recorded).

    Args:
        target: Project root

    Returns:
        Last AnalyticsEntry or None if no previous scan
    """
    project_id = get_project_id(target)
    analytics = load_project_analytics(project_id)
    if analytics is None or len(analytics.history) < 1:
        return None
    return analytics.history[-1]  # Last recorded scan


def record_scan(
    target: Path,
    score: float,
    level: str,
    violations_count: int,
    rules_checked: int,
    elapsed_ms: float,
    instruction_files: int,
) -> None:
    """
    Record a scan in global analytics (quiet collection).

    Args:
        target: Project root
        score: Validation score
        level: Capability level
        violations_count: Number of violations
        rules_checked: Number of rules checked
        elapsed_ms: Scan duration
        instruction_files: Number of instruction files scanned
    """
    project_id = get_project_id(target)
    now = datetime.now(UTC).isoformat()

    # Load or create analytics
    analytics = load_project_analytics(project_id)
    if analytics is None:
        analytics = ProjectAnalytics(
            project_id=project_id,
            project_name=get_project_name(target),
            project_path=str(target.resolve()),
            first_seen=now,
            last_seen=now,
        )

    # Update analytics
    analytics.last_seen = now
    analytics.scan_count += 1

    # Add history entry (keep last 100)
    entry = AnalyticsEntry(
        timestamp=now,
        score=score,
        level=level,
        violations_count=violations_count,
        rules_checked=rules_checked,
        elapsed_ms=elapsed_ms,
        instruction_files=instruction_files,
    )
    analytics.history.append(entry)
    analytics.history = analytics.history[-100:]  # Keep last 100

    # Save
    save_project_analytics(analytics)
