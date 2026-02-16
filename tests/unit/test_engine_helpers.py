"""Unit tests for _filter_cached_judgments from engine_helpers.

Uses tmp_path fixtures with real files and a real ProjectCache — no mocking
of filesystem or cache internals.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.cache import ProjectCache, content_hash
from reporails_cli.core.engine_helpers import _filter_cached_judgments
from reporails_cli.core.models import JudgmentRequest, Severity, Violation


def _make_request(
    rule_id: str = "C6",
    location: str = "CLAUDE.md:1",
    pass_value: str = "pass",
    severity: Severity = Severity.MEDIUM,
) -> JudgmentRequest:
    return JudgmentRequest(
        rule_id=rule_id,
        rule_title="Test",
        content="test",
        location=location,
        question="Is it good?",
        criteria={"pass_condition": "test"},
        examples={"good": [], "bad": []},
        choices=["pass", "fail"],
        pass_value=pass_value,
        severity=severity,
        points_if_fail=-10,
    )


def _make_violation(
    rule_id: str = "S1",
    location: str = "CLAUDE.md:1",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        rule_title="Existing",
        location=location,
        message="pre-existing violation",
        severity=Severity.HIGH,
    )


# ---------------------------------------------------------------------------
# _filter_cached_judgments
# ---------------------------------------------------------------------------


class TestFilterCachedJudgments:
    def test_use_cache_false_returns_unchanged(self, tmp_path: Path) -> None:
        """When use_cache=False, inputs are returned as-is."""
        requests = [_make_request()]
        violations = [_make_violation()]

        result_reqs, result_viols = _filter_cached_judgments(
            judgment_requests=requests,
            violations=violations,
            scan_root=tmp_path,
            project_root=tmp_path,
            use_cache=False,
        )

        assert result_reqs is requests
        assert result_viols is violations

    def test_empty_requests_returns_unchanged(self, tmp_path: Path) -> None:
        """When no judgment requests, returns ([], violations) unchanged."""
        violations = [_make_violation()]

        result_reqs, result_viols = _filter_cached_judgments(
            judgment_requests=[],
            violations=violations,
            scan_root=tmp_path,
            project_root=tmp_path,
            use_cache=True,
        )

        assert result_reqs == []
        assert result_viols is violations

    def test_cache_hit_pass_filters_out_request(self, tmp_path: Path) -> None:
        """Cache hit with pass verdict filters the request out, no violation added."""
        # Create the instruction file
        md_file = tmp_path / "CLAUDE.md"
        md_file.write_text("# Instructions")

        # Pre-populate cache with a passing verdict
        cache = ProjectCache(tmp_path)
        file_hash = content_hash(md_file)
        cache.set_cached_judgment(
            "CLAUDE.md",
            file_hash,
            {"C6": {"verdict": "pass", "reason": "looks good"}},
        )

        request = _make_request(rule_id="C6", location=f"{md_file}:1")
        violations: list[Violation] = []

        result_reqs, result_viols = _filter_cached_judgments(
            judgment_requests=[request],
            violations=violations,
            scan_root=tmp_path,
            project_root=tmp_path,
            use_cache=True,
        )

        assert result_reqs == []
        assert result_viols == []

    def test_cache_hit_fail_adds_violation(self, tmp_path: Path) -> None:
        """Cache hit with non-pass verdict filters the request and adds a violation."""
        md_file = tmp_path / "CLAUDE.md"
        md_file.write_text("# Instructions")

        cache = ProjectCache(tmp_path)
        file_hash = content_hash(md_file)
        cache.set_cached_judgment(
            "CLAUDE.md",
            file_hash,
            {"C6": {"verdict": "fail", "reason": "missing context"}},
        )

        request = _make_request(
            rule_id="C6",
            location=f"{md_file}:1",
            severity=Severity.HIGH,
        )
        violations: list[Violation] = []

        result_reqs, result_viols = _filter_cached_judgments(
            judgment_requests=[request],
            violations=violations,
            scan_root=tmp_path,
            project_root=tmp_path,
            use_cache=True,
        )

        assert result_reqs == []
        assert len(result_viols) == 1
        v = result_viols[0]
        assert v.rule_id == "C6"
        assert v.severity == Severity.HIGH
        assert v.message == "missing context"

    def test_cache_miss_keeps_request(self, tmp_path: Path) -> None:
        """Cache miss (no cached judgment) keeps the request in filtered list."""
        md_file = tmp_path / "CLAUDE.md"
        md_file.write_text("# Instructions")

        request = _make_request(rule_id="C6", location=f"{md_file}:1")
        violations: list[Violation] = []

        result_reqs, result_viols = _filter_cached_judgments(
            judgment_requests=[request],
            violations=violations,
            scan_root=tmp_path,
            project_root=tmp_path,
            use_cache=True,
        )

        assert len(result_reqs) == 1
        assert result_reqs[0] is request
        assert result_viols == []

    def test_file_deleted_keeps_request(self, tmp_path: Path) -> None:
        """If the file no longer exists (OSError from content_hash), request is kept."""
        # Point location at a file that does not exist
        missing = tmp_path / "gone.md"
        request = _make_request(rule_id="C6", location=f"{missing}:1")
        violations: list[Violation] = []

        result_reqs, result_viols = _filter_cached_judgments(
            judgment_requests=[request],
            violations=violations,
            scan_root=tmp_path,
            project_root=tmp_path,
            use_cache=True,
        )

        assert len(result_reqs) == 1
        assert result_reqs[0] is request
        assert result_viols == []
