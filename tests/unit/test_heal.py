"""Unit tests for heal command formatting and verdict caching.

Tests cover:
- format_judgment_prompt rendering
- format_heal_summary
- _cache_verdict integration with cache_judgments
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.cache import ProjectCache, content_hash, structural_hash
from reporails_cli.core.models import JudgmentRequest, Severity
from reporails_cli.formatters.text.heal import format_heal_summary, format_judgment_prompt
from reporails_cli.interfaces.cli.heal import _cache_verdict


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
        assert "No semantic rules" in summary


# ---------------------------------------------------------------------------
# _cache_verdict
# ---------------------------------------------------------------------------


class TestCacheVerdict:
    def test_caches_pass_verdict(self, tmp_path: Path) -> None:
        """Passing verdict is cached correctly."""
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nContent here.\n")

        jr = _make_request(location=f"{md}:1")
        _cache_verdict(tmp_path, jr, "pass", "Looks good")

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
        _cache_verdict(tmp_path, jr, "fail", "Missing TOC")

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
        _cache_verdict(tmp_path, jr, "pass", "Dismissed via ails heal")

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
