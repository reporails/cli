"""Unit tests for caching system — project-local cache and global analytics.

Uses tmp_path fixtures; only mocks subprocess calls (get_git_remote).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from reporails_cli.core.cache import (
    ProjectAnalytics,
    ProjectCache,
    content_hash,
    get_project_id,
    get_project_name,
    load_project_analytics,
    record_scan,
    save_project_analytics,
)

# ---------------------------------------------------------------------------
# content_hash
# ---------------------------------------------------------------------------


class TestContentHash:
    def test_deterministic_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "test.md"
        f.write_text("hello world")
        h1 = content_hash(f)
        h2 = content_hash(f)
        assert h1 == h2
        assert h1.startswith("sha256:")
        assert len(h1) == len("sha256:") + 16


# ---------------------------------------------------------------------------
# Project identification
# ---------------------------------------------------------------------------


class TestGetProjectId:
    def test_with_git_remote(self, tmp_path: Path) -> None:
        with patch("reporails_cli.core.analytics.get_git_remote", return_value="git@github.com:org/repo.git"):
            pid = get_project_id(tmp_path)
        assert len(pid) == 12
        assert pid.isalnum()

    def test_without_git_remote(self, tmp_path: Path) -> None:
        with patch("reporails_cli.core.analytics.get_git_remote", return_value=None):
            pid = get_project_id(tmp_path)
        assert len(pid) == 12
        assert pid.isalnum()

    def test_different_remotes_different_ids(self, tmp_path: Path) -> None:
        with patch("reporails_cli.core.analytics.get_git_remote", return_value="git@github.com:org/a.git"):
            id_a = get_project_id(tmp_path)
        with patch("reporails_cli.core.analytics.get_git_remote", return_value="git@github.com:org/b.git"):
            id_b = get_project_id(tmp_path)
        assert id_a != id_b


class TestGetProjectName:
    def test_returns_directory_name(self, tmp_path: Path) -> None:
        name = get_project_name(tmp_path)
        assert name == tmp_path.resolve().name


# ---------------------------------------------------------------------------
# ProjectCache — file map
# ---------------------------------------------------------------------------


class TestProjectCacheFileMap:
    def test_round_trip(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        # Create real files so get_cached_files validation passes
        f1 = tmp_path / "a.md"
        f2 = tmp_path / "b.md"
        f1.write_text("a")
        f2.write_text("b")

        cache.save_file_map([f1, f2])
        loaded = cache.load_file_map()

        assert loaded is not None
        assert loaded["count"] == 2
        assert set(loaded["files"]) == {"a.md", "b.md"}

    def test_returns_none_on_missing(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        assert cache.load_file_map() is None

    def test_returns_none_on_corrupt_json(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        cache.ensure_dir()
        cache.file_map_path.write_text("not json")
        assert cache.load_file_map() is None


# ---------------------------------------------------------------------------
# ProjectCache — judgment cache
# ---------------------------------------------------------------------------


class TestProjectCacheJudgment:
    def test_set_then_get_hit(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        results = {"C6": {"verdict": "pass", "reason": "ok"}}
        cache.set_cached_judgment("CLAUDE.md", "sha256:abc123", results)

        cached = cache.get_cached_judgment("CLAUDE.md", "sha256:abc123")
        assert cached == results

    def test_get_with_wrong_hash_miss(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        results = {"C6": {"verdict": "pass", "reason": "ok"}}
        cache.set_cached_judgment("CLAUDE.md", "sha256:abc123", results)

        cached = cache.get_cached_judgment("CLAUDE.md", "sha256:DIFFERENT")
        assert cached is None

    def test_get_missing_file_returns_none(self, tmp_path: Path) -> None:
        cache = ProjectCache(tmp_path)
        assert cache.get_cached_judgment("nope.md", "sha256:x") is None


# ---------------------------------------------------------------------------
# Global analytics round-trip
# ---------------------------------------------------------------------------


class TestProjectAnalytics:
    def test_save_load_round_trip(self, tmp_path: Path) -> None:
        analytics = ProjectAnalytics(
            project_id="abc123def456",
            project_name="test-project",
            project_path="/tmp/test",
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-01T00:00:00Z",
            scan_count=1,
            history=[],
        )

        with patch("reporails_cli.core.analytics.get_analytics_dir", return_value=tmp_path):
            save_project_analytics(analytics)
            loaded = load_project_analytics("abc123def456")

        assert loaded is not None
        assert loaded.project_id == "abc123def456"
        assert loaded.project_name == "test-project"
        assert loaded.scan_count == 1

    def test_load_returns_none_on_missing(self, tmp_path: Path) -> None:
        with patch("reporails_cli.core.analytics.get_analytics_dir", return_value=tmp_path):
            assert load_project_analytics("nonexistent") is None

    def test_load_returns_none_on_corrupt(self, tmp_path: Path) -> None:
        (tmp_path / "bad.json").write_text("not json")
        with patch("reporails_cli.core.analytics.get_analytics_dir", return_value=tmp_path):
            assert load_project_analytics("bad") is None


# ---------------------------------------------------------------------------
# record_scan
# ---------------------------------------------------------------------------


class TestRecordScan:
    def _record(self, target: Path, analytics_dir: Path, score: float = 7.5) -> None:
        with (
            patch("reporails_cli.core.analytics.get_git_remote", return_value=None),
            patch("reporails_cli.core.analytics.get_analytics_dir", return_value=analytics_dir),
        ):
            record_scan(
                target=target,
                score=score,
                level="L3",
                violations_count=3,
                rules_checked=10,
                elapsed_ms=50.0,
                instruction_files=1,
            )

    def test_creates_new_analytics(self, tmp_path: Path) -> None:
        target = tmp_path / "project"
        target.mkdir()
        analytics_dir = tmp_path / "analytics"

        self._record(target, analytics_dir)

        # Should have created a file
        files = list(analytics_dir.glob("*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())
        assert data["scan_count"] == 1
        assert len(data["history"]) == 1

    def test_appends_to_existing(self, tmp_path: Path) -> None:
        target = tmp_path / "project"
        target.mkdir()
        analytics_dir = tmp_path / "analytics"

        self._record(target, analytics_dir, score=6.0)
        self._record(target, analytics_dir, score=7.0)

        files = list(analytics_dir.glob("*.json"))
        assert len(files) == 1
        data = json.loads(files[0].read_text())
        assert data["scan_count"] == 2
        assert len(data["history"]) == 2

    def test_caps_at_100_entries(self, tmp_path: Path) -> None:
        target = tmp_path / "project"
        target.mkdir()
        analytics_dir = tmp_path / "analytics"

        for i in range(105):
            self._record(target, analytics_dir, score=float(i % 10))

        files = list(analytics_dir.glob("*.json"))
        data = json.loads(files[0].read_text())
        assert len(data["history"]) == 100
        assert data["scan_count"] == 105
