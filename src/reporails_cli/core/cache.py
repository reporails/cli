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

from reporails_cli.core.bootstrap import get_reporails_home


def get_analytics_dir() -> Path:
    """Get global analytics directory."""
    return get_reporails_home() / "analytics" / "projects"


def content_hash(path: Path) -> str:
    """SHA256 hash of file content for cache invalidation.

    Returns a prefixed truncated hash suitable for cache keys.
    """
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()[:16]


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
        """Save judgment cache atomically (write to temp, then rename)."""
        self.ensure_dir()
        data["version"] = 1
        data["updated_at"] = datetime.now(UTC).isoformat()
        tmp = self.judgment_cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.judgment_cache_path)

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


_VALID_VERDICTS = {"pass", "fail"}


def _parse_verdict_string(s: str) -> tuple[str, str, str, str]:
    """Parse a compact verdict string into (rule_id, location, verdict, reason).

    Handles both short IDs (``S1:CLAUDE.md:pass:reason``) and coordinate
    IDs (``CORE:S:0001:CLAUDE.md:pass:reason``), including an optional
    line-number suffix on the location (``CLAUDE.md:42``).

    The verdict field is always ``pass`` or ``fail``; we scan for it to
    resolve ambiguity introduced by colons in rule IDs or locations.

    Returns ("", "", "", "") for unparseable input.
    """
    parts = s.split(":")
    if len(parts) < 3:
        return ("", "", "", "")

    # Determine rule_id width: 3 parts for coordinate IDs, 1 for short
    is_coordinate = (
        len(parts) >= 5
        and parts[0].isalpha()
        and len(parts[2]) == 4
        and parts[2].isdigit()
    )
    id_width = 3 if is_coordinate else 1

    # Scan remaining parts for the verdict token (pass/fail)
    rest = parts[id_width:]
    verdict_idx = None
    for i, p in enumerate(rest):
        if p in _VALID_VERDICTS:
            verdict_idx = i
            break

    if verdict_idx is None or verdict_idx < 1:
        # No verdict found, or nothing before it for location
        return ("", "", "", "")

    rule_id = ":".join(parts[:id_width])
    location = ":".join(rest[:verdict_idx])
    verdict = rest[verdict_idx]
    reason = ":".join(rest[verdict_idx + 1 :])
    return (rule_id, location, verdict, reason)


def cache_judgments(target: Path, judgments: list[Any]) -> int:
    """Cache semantic judgment verdicts for a project.

    Accepts verdicts as either compact strings ("rule_id:location:verdict:reason")
    or dicts with rule_id, location, verdict, reason keys.

    Args:
        target: Project root path (scan root — project root resolved automatically)
        judgments: List of verdict strings or dicts

    Returns:
        Count of successfully recorded judgments
    """
    from reporails_cli.core.engine import _find_project_root

    project_root = _find_project_root(target)
    cache = ProjectCache(project_root)
    recorded = 0

    # Load cache once, accumulate changes, save once (atomic)
    cache_data = cache.load_judgment_cache()
    cache_judgments_dict = cache_data.setdefault("judgments", {})

    for j in judgments:
        if isinstance(j, str):
            rule_id, location, verdict, reason = _parse_verdict_string(j)
        else:
            rule_id = j.get("rule_id", "")
            location = j.get("location", "")
            verdict = j.get("verdict", "")
            reason = j.get("reason", "")

        if not rule_id or not location or not verdict:
            continue

        # Strip line number from location to get file path
        file_path = location.rsplit(":", 1)[0] if ":" in location else location
        full_path = (target / file_path).resolve()

        # Guard: file must exist and be within the target directory
        if not full_path.exists():
            continue
        try:
            file_path = str(full_path.relative_to(target.resolve()))
        except ValueError:
            continue  # Path traversal — outside project root

        try:
            file_hash = content_hash(full_path)
        except OSError:
            continue

        # Merge verdict into in-memory cache
        entry = cache_judgments_dict.get(file_path, {})
        if entry.get("content_hash") != file_hash:
            # File changed — reset cached results for this file
            entry = {"content_hash": file_hash, "results": {}}
        results = entry.setdefault("results", {})
        results[rule_id] = {
            "verdict": verdict,
            "reason": reason,
        }
        entry["content_hash"] = file_hash
        entry["evaluated_at"] = datetime.now(UTC).isoformat()
        cache_judgments_dict[file_path] = entry
        recorded += 1

    if recorded > 0:
        cache.save_judgment_cache(cache_data)

    return recorded


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
