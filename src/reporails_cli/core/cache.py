"""Caching system - project-local for operations, global for analytics.

Project-local (.reporails/):
  - backbone.yml           # Project structure (committed)
  - .cache/file-map.json   # Fast file lookup (gitignored)
  - .cache/judgment-cache.json  # Semantic judgment results (gitignored)

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
from typing import Any


def get_reporails_home() -> Path:
    """Get global reporails directory (~/.reporails/)."""
    return Path.home() / ".reporails"


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
# Project-Local Cache (.reporails/)
# =============================================================================


@dataclass
class ProjectCache:
    """Project-local cache manager."""

    target: Path

    @property
    def reporails_dir(self) -> Path:
        """Get project's .reporails directory."""
        return self.target / ".reporails"

    @property
    def cache_dir(self) -> Path:
        """Get project's cache directory (.reporails/.cache/)."""
        return self.reporails_dir / ".cache"

    @property
    def file_map_path(self) -> Path:
        return self.cache_dir / "file-map.json"

    @property
    def backbone_path(self) -> Path:
        return self.reporails_dir / "backbone.yml"

    @property
    def judgment_cache_path(self) -> Path:
        return self.cache_dir / "judgment-cache.json"

    def ensure_dir(self) -> None:
        """Create cache directory if needed."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # File map operations
    def load_file_map(self) -> dict[str, Any] | None:
        """Load cached file map."""
        if not self.file_map_path.exists():
            return None
        try:
            result: dict[str, Any] = json.loads(self.file_map_path.read_text(encoding="utf-8"))
            return result
        except (json.JSONDecodeError, OSError):
            return None

    def save_file_map(self, files: list[Path]) -> None:
        """Save file map to cache."""
        self.ensure_dir()
        relative_paths = [str(f.relative_to(self.target)) for f in files]
        data = {
            "version": 1,
            "target": str(self.target),
            "files": relative_paths,
            "count": len(files),
            "cached_at": datetime.now(UTC).isoformat(),
        }
        self.file_map_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_cached_files(self) -> list[Path] | None:
        """Get files from cache if valid."""
        data = self.load_file_map()
        if data is None:
            return None

        files = [self.target / p for p in data.get("files", [])]
        # Validate: check if files still exist
        if all(f.exists() for f in files):
            return files
        return None

    # Judgment cache operations
    def load_judgment_cache(self) -> dict[str, Any]:
        """Load cached semantic judgments."""
        if not self.judgment_cache_path.exists():
            return {"version": 1, "judgments": {}}
        try:
            result: dict[str, Any] = json.loads(
                self.judgment_cache_path.read_text(encoding="utf-8")
            )
            return result
        except (json.JSONDecodeError, OSError):
            return {"version": 1, "judgments": {}}

    def save_judgment_cache(self, data: dict[str, Any]) -> None:
        """Save judgment cache."""
        self.ensure_dir()
        data["version"] = 1
        data["updated_at"] = datetime.now(UTC).isoformat()
        self.judgment_cache_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def get_cached_judgment(self, file_path: str, content_hash: str) -> dict[str, Any] | None:
        """Get cached judgment for a file if hash matches."""
        cache = self.load_judgment_cache()
        judgments = cache.get("judgments", {})

        if file_path not in judgments:
            return None

        entry = judgments[file_path]
        if entry.get("content_hash") != content_hash:
            return None  # File changed, cache invalid

        results: dict[str, Any] | None = entry.get("results")
        return results

    def set_cached_judgment(
        self, file_path: str, content_hash: str, results: dict[str, Any]
    ) -> None:
        """Cache judgment results for a file."""
        cache = self.load_judgment_cache()
        cache.setdefault("judgments", {})[file_path] = {
            "content_hash": content_hash,
            "evaluated_at": datetime.now(UTC).isoformat(),
            "results": results,
        }
        self.save_judgment_cache(cache)


# =============================================================================
# Global Analytics Cache (~/.reporails/analytics/)
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
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


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
