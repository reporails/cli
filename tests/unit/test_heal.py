"""Unit tests for heal command formatting and verdict caching.

Tests cover:
- format_judgment_prompt rendering
- format_heal_summary
- _cache_verdict integration with cache_judgments
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.cache import ProjectCache, content_hash, structural_hash
from reporails_cli.core.models import JudgmentRequest, Severity, Violation
from reporails_cli.formatters.text.heal import (
    extract_violation_snippet,
    format_fixable_violation_prompt,
    format_heal_summary,
    format_judgment_prompt,
    format_violation_prompt,
)
from reporails_cli.interfaces.cli.heal_prompts import cache_verdict, cache_violation_dismissal


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
# format_judgment_prompt
# ---------------------------------------------------------------------------


class TestFormatJudgmentPrompt:
    def test_contains_rule_info(self) -> None:
        jr = _make_request()
        output = format_judgment_prompt(jr, 2, 5)
        assert "Rule 2/5" in output
        assert "CORE:C:0019" in output
        assert "Navigability Aid" in output

    def test_contains_question(self) -> None:
        jr = _make_request()
        output = format_judgment_prompt(jr, 1, 1)
        assert "Does this file include navigation aids?" in output

    def test_contains_criteria(self) -> None:
        jr = _make_request()
        output = format_judgment_prompt(jr, 1, 1)
        assert "Has table of contents" in output
        assert "Section headers provide navigation" in output

    def test_contains_action_prompt(self) -> None:
        jr = _make_request()
        output = format_judgment_prompt(jr, 1, 1)
        assert "[p]ass" in output
        assert "[f]ail" in output
        assert "[s]kip" in output
        assert "[d]ismiss" in output

    def test_contains_file_path(self) -> None:
        jr = _make_request(location="CLAUDE.md:42")
        output = format_judgment_prompt(jr, 1, 1)
        assert "CLAUDE.md" in output

    def test_contains_content_snippet(self) -> None:
        jr = _make_request()
        output = format_judgment_prompt(jr, 1, 1)
        assert "# My Project" in output
        assert "Section 1" in output

    def test_ascii_mode(self) -> None:
        jr = _make_request()
        output = format_judgment_prompt(jr, 1, 1, ascii_mode=True)
        # ASCII mode uses + for corners, - for horizontal
        assert "+" in output
        assert "-" in output
        # Should NOT contain Unicode box chars
        assert "\u2554" not in output  # ╔

    def test_unicode_mode(self) -> None:
        jr = _make_request()
        output = format_judgment_prompt(jr, 1, 1, ascii_mode=False)
        assert "\u2554" in output  # ╔

    def test_severity_shown(self) -> None:
        jr = _make_request(severity=Severity.HIGH)
        output = format_judgment_prompt(jr, 1, 1)
        assert "HIGH" in output

    def test_truncates_long_content(self) -> None:
        long_content = "\n".join(f"Line {i}" for i in range(100))
        jr = JudgmentRequest(
            rule_id="C6",
            rule_title="Test",
            content=long_content,
            location="CLAUDE.md:1",
            question="Is it good?",
            criteria={"check": "test"},
            examples={"good": [], "bad": []},
            choices=["pass", "fail"],
            pass_value="pass",
            severity=Severity.MEDIUM,
            points_if_fail=-10,
        )
        output = format_judgment_prompt(jr, 1, 1, max_content_lines=10)
        assert "first 10 lines" in output
        # Should contain early lines
        assert "Line 0" in output
        # Should NOT contain lines beyond the limit
        assert "Line 50" not in output


# ---------------------------------------------------------------------------
# format_heal_summary
# ---------------------------------------------------------------------------


class TestFormatHealSummary:
    def test_all_actions(self) -> None:
        summary = format_heal_summary(passed=3, failed=1, skipped=1, dismissed=2)
        assert "3 passed" in summary
        assert "1 failed" in summary
        assert "1 skipped" in summary
        assert "2 dismissed" in summary
        assert summary.startswith("Heal complete:")

    def test_only_passed(self) -> None:
        summary = format_heal_summary(passed=5, failed=0, skipped=0, dismissed=0)
        assert "5 passed" in summary
        assert "failed" not in summary
        assert "skipped" not in summary

    def test_no_actions(self) -> None:
        summary = format_heal_summary(passed=0, failed=0, skipped=0, dismissed=0)
        assert "Nothing to heal" in summary

    def test_with_auto_fixed(self) -> None:
        summary = format_heal_summary(passed=0, failed=0, skipped=0, dismissed=0, auto_fixed=3)
        assert "3 applied" in summary
        assert summary.startswith("Heal complete:")

    def test_with_violations_dismissed(self) -> None:
        summary = format_heal_summary(passed=1, failed=0, skipped=0, dismissed=1, violations_dismissed=2)
        assert "3 dismissed" in summary  # 2 violations + 1 semantic
        assert "1 passed" in summary

    def test_with_violations_skipped(self) -> None:
        summary = format_heal_summary(passed=0, failed=0, skipped=0, dismissed=0, violations_skipped=3)
        assert "3 violations skipped" in summary


# ---------------------------------------------------------------------------
# _cache_verdict
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
    """Test the --non-interactive flag for heal command."""

    def test_json_format_with_no_fixes(self) -> None:
        """Non-interactive mode outputs valid JSON when no fixes are needed."""
        from reporails_cli.formatters.json import format_heal_result

        result = format_heal_result([], [])
        assert result["auto_fixed"] == []
        assert result["judgment_requests"] == []
        assert result["summary"]["auto_fixed_count"] == 0
        assert result["summary"]["pending_judgments"] == 0

    def test_json_format_with_auto_fixes(self) -> None:
        """Non-interactive mode includes auto-fix details in JSON."""
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
        """Non-interactive mode includes judgment requests in JSON."""
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
        """Non-interactive mode handles both auto-fixes and judgment requests."""
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
        """Non-interactive mode includes non-fixable violations in JSON."""
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
# format_fixable_violation_prompt
# ---------------------------------------------------------------------------


class TestFormatFixableViolationPrompt:
    def test_contains_rule_info(self) -> None:
        v = _make_violation(rule_id="CORE:C:0003", rule_title="Has Commands")
        output = format_fixable_violation_prompt(v, "Append a ## Commands section", 1, 3)
        assert "Fix 1/3" in output
        assert "CORE:C:0003" in output
        assert "Has Commands" in output

    def test_contains_fix_description(self) -> None:
        v = _make_violation()
        output = format_fixable_violation_prompt(v, "Append a ## Commands section", 1, 1)
        assert "Proposed fix:" in output
        assert "Append a ## Commands section" in output

    def test_contains_action_prompt(self) -> None:
        v = _make_violation()
        output = format_fixable_violation_prompt(v, "fix it", 1, 1)
        assert "[a]pply" in output
        assert "[s]kip" in output
        assert "[d]ismiss" in output

    def test_ascii_mode(self) -> None:
        v = _make_violation()
        output = format_fixable_violation_prompt(v, "fix", 1, 1, ascii_mode=True)
        assert "+" in output
        assert "\u2554" not in output  # No Unicode


# ---------------------------------------------------------------------------
# format_violation_prompt
# ---------------------------------------------------------------------------


class TestFormatViolationPrompt:
    def test_contains_rule_info(self) -> None:
        v = _make_violation()
        output = format_violation_prompt(v, 2, 5)
        assert "Violation 2/5" in output
        assert "CORE:S:0003" in output
        assert "Wall of Prose" in output

    def test_contains_message(self) -> None:
        v = _make_violation(message="Too long paragraph")
        output = format_violation_prompt(v, 1, 1)
        assert "Too long paragraph" in output

    def test_contains_action_prompt(self) -> None:
        v = _make_violation()
        output = format_violation_prompt(v, 1, 1)
        assert "[d]ismiss" in output
        assert "[s]kip" in output

    def test_with_snippet(self) -> None:
        v = _make_violation()
        snippet = "  >> 17 | This is the offending line"
        output = format_violation_prompt(v, 1, 1, snippet=snippet)
        assert "offending line" in output

    def test_without_snippet(self) -> None:
        v = _make_violation()
        output = format_violation_prompt(v, 1, 1, snippet=None)
        assert "File:" in output
        # Should still render without error


# ---------------------------------------------------------------------------
# _cache_violation_dismissal
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
