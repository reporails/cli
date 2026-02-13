"""Caching system — project-local cache and hash functions for cache invalidation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Re-exports for backward compatibility (explicit re-export via `as` for mypy)
from reporails_cli.core.analytics import AnalyticsEntry as AnalyticsEntry
from reporails_cli.core.analytics import ProjectAnalytics as ProjectAnalytics
from reporails_cli.core.analytics import get_analytics_dir as get_analytics_dir
from reporails_cli.core.analytics import get_git_remote as get_git_remote
from reporails_cli.core.analytics import get_previous_scan as get_previous_scan
from reporails_cli.core.analytics import get_project_analytics_path as get_project_analytics_path
from reporails_cli.core.analytics import get_project_id as get_project_id
from reporails_cli.core.analytics import get_project_name as get_project_name
from reporails_cli.core.analytics import load_project_analytics as load_project_analytics
from reporails_cli.core.analytics import record_scan as record_scan
from reporails_cli.core.analytics import save_project_analytics as save_project_analytics


def content_hash(path: Path) -> str:
    """SHA256 hash of file content, prefixed and truncated for cache keys."""
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def structural_hash(path: Path) -> str:
    """Hash of semantic-relevant structure: headings, constraint lines, list items.

    Cosmetic edits (whitespace, prose) keep the same structural hash, allowing
    cached semantic verdicts to survive as stale-but-usable.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    structural_lines = [
        line.strip()
        for line in lines
        if line.strip().startswith("#")
        or "MUST" in line
        or "NEVER" in line
        or "ALWAYS" in line
        or "IMPORTANT" in line
        or line.strip().startswith("- ")
    ]
    blob = "\n".join(structural_lines).encode("utf-8")
    return "struct:" + hashlib.sha256(blob).hexdigest()[:16]


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
            result: dict[str, Any] = json.loads(self.judgment_cache_path.read_text(encoding="utf-8"))
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

    def get_cached_judgment(
        self,
        file_path: str,
        content_hash: str,
        structural_hash: str | None = None,
    ) -> dict[str, Any] | None:
        """Three-tier lookup: content match (fresh) → structural match (stale) → None."""
        cache = self.load_judgment_cache()
        judgments = cache.get("judgments", {})

        if file_path not in judgments:
            return None

        entry = judgments[file_path]

        # Tier 1: exact content match (fresh)
        if entry.get("content_hash") == content_hash:
            results: dict[str, Any] | None = entry.get("results")
            return results

        # Tier 2: structural match (stale but usable)
        if structural_hash and entry.get("structural_hash") == structural_hash:
            results = entry.get("results")
            return results

        # Tier 3: both differ — invalidated
        return None

    def set_cached_judgment(
        self,
        file_path: str,
        content_hash: str,
        results: dict[str, Any],
        structural_hash: str | None = None,
    ) -> None:
        """Cache judgment results for a file (with optional structural hash)."""
        cache = self.load_judgment_cache()
        entry: dict[str, Any] = {
            "content_hash": content_hash,
            "evaluated_at": datetime.now(UTC).isoformat(),
            "results": results,
        }
        if structural_hash:
            entry["structural_hash"] = structural_hash
        cache.setdefault("judgments", {})[file_path] = entry
        self.save_judgment_cache(cache)


# =============================================================================
# Verdict Parsing & Judgment Caching
# =============================================================================

_VALID_VERDICTS = {"pass", "fail"}


def _parse_verdict_string(s: str) -> tuple[str, str, str, str]:
    """Parse ``rule_id:location:verdict:reason`` — supports short and coordinate IDs."""
    parts = s.split(":")
    if len(parts) < 3:
        return ("", "", "", "")

    # Determine rule_id width: 3 parts for coordinate IDs, 1 for short
    is_coordinate = len(parts) >= 5 and parts[0].isalpha() and len(parts[2]) == 4 and parts[2].isdigit()
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


def cache_judgments(target: Path, judgments: list[Any]) -> int:  # pylint: disable=too-many-locals
    """Cache semantic judgment verdicts for a project."""
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
            continue  # Path traversal -- outside project root

        try:
            file_hash = content_hash(full_path)
            struct_hash = structural_hash(full_path)
        except OSError:
            continue

        # Merge verdict into in-memory cache
        entry = cache_judgments_dict.get(file_path, {})
        if entry.get("content_hash") != file_hash:
            # File changed -- reset cached results for this file
            entry = {"content_hash": file_hash, "structural_hash": struct_hash, "results": {}}
        results = entry.setdefault("results", {})
        results[rule_id] = {
            "verdict": verdict,
            "reason": reason,
        }
        entry["content_hash"] = file_hash
        entry["structural_hash"] = struct_hash
        entry["evaluated_at"] = datetime.now(UTC).isoformat()
        cache_judgments_dict[file_path] = entry
        recorded += 1

    if recorded > 0:
        cache.save_judgment_cache(cache_data)

    return recorded
