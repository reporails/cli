"""Unit tests for heal command formatting and verdict caching.

Tests cover:
- format_heal_summary rendering (autoheal output)
- cache_verdict integration with cache_judgments
- cache_violation_dismissal
- extract_violation_snippet
- Non-interactive JSON output (format_heal_result)
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.cache import (
    ProjectCache,
    cache_verdict,
    cache_violation_dismissal,
    content_hash,
    structural_hash,
)
from reporails_cli.core.fixers import FixResult
from reporails_cli.core.models import JudgmentRequest, Severity, Violation
from reporails_cli.formatters.text.heal import extract_violation_snippet, format_heal_summary


def _make_request(
    rule_id: str = "CORE:C:0019",
    rule_title: str = "Navigability Aid",
    location: str = "CLAUDE.md:1",
    question: str = "Does this file include navigation aids?",
    severity: Severity = Severity.MEDIUM,
) -> JudgmentRequest:
    return JudgmentRequest(
        rule_id=rule_id,
        rule_title=rule_title,
        content="# My Project\n\nSome content here.\n\n## Section 1\n\nMore content.",
        location=location,
        question=question,
        criteria={"toc": "Has table of contents", "headers": "Section headers provide navigation"},
        examples={"good": ["# Project\n## TOC"], "bad": ["wall of text"]},
        choices=["pass", "fail"],
        pass_value="pass",
        severity=severity,
        points_if_fail=-10,
    )


# ---------------------------------------------------------------------------
# Violation helpers
# ---------------------------------------------------------------------------


def _make_violation(
    rule_id: str = "CORE:S:0003",
    rule_title: str = "Wall of Prose",
    location: str = "CLAUDE.md:17",
    message: str = "Paragraph exceeds 5 lines without structure",
    severity: Severity = Severity.MEDIUM,
) -> Violation:
    return Violation(
        rule_id=rule_id,
        rule_title=rule_title,
        location=location,
        message=message,
        severity=severity,
    )


# ---------------------------------------------------------------------------
# format_heal_summary
# ---------------------------------------------------------------------------


class TestFormatHealSummary:
    def test_applied_fixes_shown(self) -> None:
        fixes = [
            FixResult(
                rule_id="CORE:C:0003", file_path="CLAUDE.md", description="Added ## Commands section to CLAUDE.md"
            ),
        ]
        summary = format_heal_summary(fixes, [], [])
        assert "Applied 1 fix(es):" in summary
        assert "CORE:C:0003" in summary
        assert "Added ## Commands section" in summary

    def test_remaining_violations_shown(self) -> None:
        violations = [_make_violation()]
        summary = format_heal_summary([], violations, [])
        assert "1 remaining violation(s):" in summary
        assert "CORE:S:0003" in summary
        assert "CLAUDE.md:17" in summary

    def test_pending_semantic_shown(self) -> None:
        requests = [_make_request()]
        summary = format_heal_summary([], [], requests)
        assert "1 semantic rule(s) pending evaluation:" in summary
        assert "CORE:C:0019" in summary
        assert "Navigability Aid" in summary

    def test_nothing_to_heal(self) -> None:
        summary = format_heal_summary([], [], [])
        assert "Nothing to heal" in summary

    def test_all_sections(self) -> None:
        fixes = [FixResult(rule_id="CORE:C:0003", file_path="CLAUDE.md", description="Added ## Commands")]
        violations = [_make_violation()]
        requests = [_make_request()]
        summary = format_heal_summary(fixes, violations, requests)
        assert "Applied 1 fix(es):" in summary
        assert "1 remaining violation(s):" in summary
        assert "1 semantic rule(s) pending evaluation:" in summary

    def test_ascii_mode_uses_plus(self) -> None:
        fixes = [FixResult(rule_id="CORE:C:0003", file_path="CLAUDE.md", description="Added ## Commands")]
        summary = format_heal_summary(fixes, [], [], ascii_mode=True)
        assert "+" in summary
        assert "\u2713" not in summary  # No Unicode checkmark


# ---------------------------------------------------------------------------
# cache_verdict
# ---------------------------------------------------------------------------


class TestCacheVerdict:
    def test_caches_pass_verdict(self, tmp_path: Path) -> None:
        """Passing verdict is cached correctly."""
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nContent here.\n")

        jr = _make_request(location=f"{md}:1")
        cache_verdict(tmp_path, jr, "pass", "Looks good")

        cache = ProjectCache(tmp_path)
        file_hash = content_hash(md)
        struct_hash = structural_hash(md)
        cached = cache.get_cached_judgment("CLAUDE.md", file_hash, structural_hash=struct_hash)
        assert cached is not None
        assert "CORE:C:0019" in cached
        assert cached["CORE:C:0019"]["verdict"] == "pass"

    def test_caches_fail_verdict(self, tmp_path: Path) -> None:
        """Failing verdict with reason is cached correctly."""
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nContent here.\n")

        jr = _make_request(location=f"{md}:1")
        cache_verdict(tmp_path, jr, "fail", "Missing TOC")

        cache = ProjectCache(tmp_path)
        file_hash = content_hash(md)
        struct_hash = structural_hash(md)
        cached = cache.get_cached_judgment("CLAUDE.md", file_hash, structural_hash=struct_hash)
        assert cached is not None
        assert cached["CORE:C:0019"]["verdict"] == "fail"
        assert cached["CORE:C:0019"]["reason"] == "Missing TOC"

    def test_dismiss_caches_as_pass(self, tmp_path: Path) -> None:
        """Dismiss action caches as pass verdict."""
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nContent.\n")

        jr = _make_request(location=f"{md}:1")
        cache_verdict(tmp_path, jr, "pass", "Dismissed via ails heal")

        cache = ProjectCache(tmp_path)
        file_hash = content_hash(md)
        cached = cache.get_cached_judgment("CLAUDE.md", file_hash)
        assert cached is not None
        assert cached["CORE:C:0019"]["verdict"] == "pass"
        assert "Dismissed" in cached["CORE:C:0019"]["reason"]


# ---------------------------------------------------------------------------
# Non-interactive mode (JSON output)
# ---------------------------------------------------------------------------


class TestNonInteractiveMode:
    """Test the JSON formatter for heal command."""

    def test_json_format_with_no_fixes(self) -> None:
        """JSON output is valid when no fixes are needed."""
        from reporails_cli.formatters.json import format_heal_result

        result = format_heal_result([], [])
        assert result["auto_fixed"] == []
        assert result["judgment_requests"] == []
        assert result["summary"]["auto_fixed_count"] == 0
        assert result["summary"]["pending_judgments"] == 0

    def test_json_format_with_auto_fixes(self) -> None:
        """JSON output includes auto-fix details."""
        from reporails_cli.formatters.json import format_heal_result

        auto_fixed = [
            {
                "rule_id": "CORE:S:0001",
                "file_path": "CLAUDE.md",
                "description": "Added root instruction file",
            }
        ]
        result = format_heal_result(auto_fixed, [])
        assert len(result["auto_fixed"]) == 1
        assert result["auto_fixed"][0]["rule_id"] == "CORE:S:0001"
        assert result["summary"]["auto_fixed_count"] == 1

    def test_json_format_with_judgment_requests(self) -> None:
        """JSON output includes judgment requests."""
        from reporails_cli.formatters.json import format_heal_result

        judgment_requests = [
            {
                "rule_id": "CORE:C:0019",
                "rule_title": "Navigability Aid",
                "question": "Does this file include navigation aids?",
                "content": "# Project",
                "location": "CLAUDE.md:1",
                "criteria": {"toc": "Has TOC"},
                "examples": {"good": [], "bad": []},
                "choices": ["pass", "fail"],
                "pass_value": "pass",
            }
        ]
        result = format_heal_result([], judgment_requests)
        assert len(result["judgment_requests"]) == 1
        assert result["judgment_requests"][0]["rule_id"] == "CORE:C:0019"
        assert result["summary"]["pending_judgments"] == 1

    def test_json_format_with_both(self) -> None:
        """JSON output handles both auto-fixes and judgment requests."""
        from reporails_cli.formatters.json import format_heal_result

        auto_fixed = [{"rule_id": "CORE:S:0001", "file_path": "CLAUDE.md", "description": "Added file"}]
        judgment_requests = [
            {
                "rule_id": "CORE:C:0019",
                "rule_title": "Nav",
                "question": "Good?",
                "content": "# P",
                "location": "CLAUDE.md:1",
                "criteria": {},
                "examples": {"good": [], "bad": []},
                "choices": ["pass", "fail"],
                "pass_value": "pass",
            }
        ]
        result = format_heal_result(auto_fixed, judgment_requests)
        assert result["summary"]["auto_fixed_count"] == 1
        assert result["summary"]["pending_judgments"] == 1

    def test_json_format_with_violations(self) -> None:
        """JSON output includes non-fixable violations."""
        from reporails_cli.formatters.json import format_heal_result

        violations = [
            {
                "rule_id": "CORE:S:0003",
                "rule_title": "Wall of Prose",
                "location": "CLAUDE.md:15",
                "message": "Paragraph exceeds 5 lines",
                "severity": "medium",
            }
        ]
        result = format_heal_result([], [], violations=violations)
        assert "violations" in result
        assert len(result["violations"]) == 1
        assert result["summary"]["violations_count"] == 1


# ---------------------------------------------------------------------------
# extract_violation_snippet
# ---------------------------------------------------------------------------


class TestExtractViolationSnippet:
    def test_returns_snippet_with_marker(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("line 1\nline 2\nline 3\nline 4\nline 5\n")
        snippet = extract_violation_snippet(f"{md}:3", tmp_path)
        assert snippet is not None
        assert ">>" in snippet
        assert "line 3" in snippet
        # Context lines should be present
        assert "line 1" in snippet
        assert "line 5" in snippet

    def test_returns_none_for_no_line_number(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("some content\n")
        snippet = extract_violation_snippet(str(md), tmp_path)
        assert snippet is None

    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        snippet = extract_violation_snippet(f"{tmp_path}/missing.md:5", tmp_path)
        assert snippet is None

    def test_relative_path(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("a\nb\nc\nd\ne\n")
        snippet = extract_violation_snippet("CLAUDE.md:3", tmp_path)
        assert snippet is not None
        assert ">>" in snippet

    def test_target_line_at_boundary(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("first\nsecond\n")
        snippet = extract_violation_snippet(f"{md}:1", tmp_path)
        assert snippet is not None
        assert ">> " in snippet
        assert "first" in snippet


# ---------------------------------------------------------------------------
# cache_violation_dismissal
# ---------------------------------------------------------------------------


class TestCacheViolationDismissal:
    def test_caches_as_pass(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nContent here.\n")

        v = _make_violation(location=f"{md}:17")
        cache_violation_dismissal(tmp_path, v)

        cache = ProjectCache(tmp_path)
        file_hash = content_hash(md)
        struct_hash = structural_hash(md)
        cached = cache.get_cached_judgment("CLAUDE.md", file_hash, structural_hash=struct_hash)
        assert cached is not None
        assert "CORE:S:0003" in cached
        assert cached["CORE:S:0003"]["verdict"] == "pass"
        assert "Dismissed" in cached["CORE:S:0003"]["reason"]

    def test_dismissed_violation_filtered_by_engine(self, tmp_path: Path) -> None:
        """Dismissed violations are filtered out by _filter_dismissed_violations."""
        from reporails_cli.core.engine_helpers import _filter_dismissed_violations

        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nContent here.\n")

        v = _make_violation(location="CLAUDE.md:17")
        cache_violation_dismissal(tmp_path, v)

        # Now filter — should remove the dismissed violation
        result = _filter_dismissed_violations([v], tmp_path, tmp_path, use_cache=True)
        assert len(result) == 0

    def test_refresh_bypasses_dismissal(self, tmp_path: Path) -> None:
        """--refresh (use_cache=False) ignores dismissals."""
        from reporails_cli.core.engine_helpers import _filter_dismissed_violations

        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nContent here.\n")

        v = _make_violation(location="CLAUDE.md:17")
        cache_violation_dismissal(tmp_path, v)

        # With use_cache=False, dismissal is ignored
        result = _filter_dismissed_violations([v], tmp_path, tmp_path, use_cache=False)
        assert len(result) == 1
