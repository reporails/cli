"""End-to-end MCP tool tests — exercise all tools through the server dispatch layer.

Covers:
  - Tool listing: all expected tools present with correct schemas
  - validate: returns JSON with score, violations, judgment workflow
  - score: returns JSON with score/level keys
  - explain: returns rule details or error for unknown rules
  - judge: caches verdicts, returns recorded count
  - judge: path traversal blocked, coordinate IDs parsed correctly
  - Circuit breaker: content-aware mtime tracking
  - Unknown tool: returns error
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rules_installed() -> bool:
    from reporails_cli.core.bootstrap import get_rules_path

    return (get_rules_path() / "core").exists()


requires_rules = pytest.mark.skipif(
    not _rules_installed(),
    reason="Rules framework not installed",
)


def _run_async(coro: Any) -> Any:
    """Run an async function synchronously."""
    return asyncio.run(coro)


def _call_tool(name: str, arguments: dict[str, Any]) -> str:
    """Call an MCP tool and return the text content."""
    from reporails_cli.interfaces.mcp.server import call_tool

    results = _run_async(call_tool(name, arguments))
    assert len(results) == 1
    return results[0].text


# ---------------------------------------------------------------------------
# Tool listing
# ---------------------------------------------------------------------------


class TestListTools:
    def test_all_tools_present(self) -> None:
        """list_tools should return all five tools."""
        from reporails_cli.interfaces.mcp.server import list_tools

        tools = _run_async(list_tools())
        names = {t.name for t in tools}
        assert names == {"validate", "score", "explain", "judge", "heal"}

    def test_judge_tool_has_required_verdicts(self) -> None:
        """judge tool schema should require the verdicts parameter."""
        from reporails_cli.interfaces.mcp.server import list_tools

        tools = _run_async(list_tools())
        judge = next(t for t in tools if t.name == "judge")
        assert "verdicts" in judge.inputSchema["required"]

    def test_validate_tool_path_optional(self) -> None:
        """validate tool should not require path (has default)."""
        from reporails_cli.interfaces.mcp.server import list_tools

        tools = _run_async(list_tools())
        validate = next(t for t in tools if t.name == "validate")
        assert "required" not in validate.inputSchema


# ---------------------------------------------------------------------------
# validate tool
# ---------------------------------------------------------------------------

# Shell-out patterns that must NEVER appear in validate output.
_SHELL_OUT_PATTERNS = [
    "via Bash",
    "via bash",
    "ails judge .",
    "ails judge",
    "npx ",
    "run this command",
    "shell command",
    "bash -c",
    "subprocess",
    "terminal",
]


class TestValidateTool:
    @requires_rules
    def test_returns_valid_json(self, level2_project: Path) -> None:
        """validate must return parseable JSON."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)  # Must not raise
        assert isinstance(data, dict)

    @requires_rules
    def test_json_has_score(self, level2_project: Path) -> None:
        """validate JSON must contain a score key."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "score" in data
        assert isinstance(data["score"], (int, float))

    @requires_rules
    def test_json_has_violations_array(self, level2_project: Path) -> None:
        """validate JSON must contain violations as a list."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "violations" in data
        assert isinstance(data["violations"], list)

    @requires_rules
    def test_json_has_level(self, level2_project: Path) -> None:
        """validate JSON must contain level."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "level" in data
        assert data["level"].startswith("L")

    @requires_rules
    def test_no_shell_out_guidance(self, level2_project: Path) -> None:
        """REGRESSION: validate must never tell the LLM to shell out."""
        text = _call_tool("validate", {"path": str(level2_project)})
        for pattern in _SHELL_OUT_PATTERNS:
            assert pattern not in text, f"Shell-out pattern {pattern!r} found in validate response"

    @requires_rules
    def test_semantic_workflow_when_pending(self, level2_project: Path) -> None:
        """When semantic rules exist, JSON must contain _semantic_workflow."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        if data.get("judgment_requests"):
            assert "_semantic_workflow" in data
            workflow = data["_semantic_workflow"]
            assert workflow["action"] == "evaluate_and_judge"
            assert "steps" in workflow
            assert "verdict_format" in workflow
            assert "example_call" in workflow

    def test_missing_path_returns_error_json(self) -> None:
        """Non-existent path should return JSON error."""
        text = _call_tool("validate", {"path": "/tmp/no-such-path-xyz-mcp-test"})
        data = json.loads(text)
        assert "error" in data

    def test_uninitialized_returns_error_json(self) -> None:
        """When framework is not initialized, should return JSON error."""
        with patch("reporails_cli.interfaces.mcp.server.is_initialized", return_value=False):
            text = _call_tool("validate", {"path": "."})
        data = json.loads(text)
        assert "error" in data
        assert data["error"] == "not_initialized"

    def test_runtime_error_returns_error_json(self, level2_project: Path) -> None:
        """RuntimeError from run_validation must return JSON error, not crash."""
        with patch(
            "reporails_cli.interfaces.mcp.server.run_validation",
            side_effect=RuntimeError("Unsupported operating system"),
        ):
            text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "error" in data
        assert data["error"] == "RuntimeError"


# ---------------------------------------------------------------------------
# score tool
# ---------------------------------------------------------------------------


class TestScoreTool:
    @requires_rules
    def test_returns_json_with_score(self, level2_project: Path) -> None:
        """score should return JSON with score and level."""
        text = _call_tool("score", {"path": str(level2_project)})
        data = json.loads(text)
        assert "score" in data
        assert "level" in data

    @requires_rules
    def test_score_is_numeric(self, level2_project: Path) -> None:
        """Score value should be a number."""
        text = _call_tool("score", {"path": str(level2_project)})
        data = json.loads(text)
        assert isinstance(data["score"], (int, float))


# ---------------------------------------------------------------------------
# explain tool
# ---------------------------------------------------------------------------


class TestExplainTool:
    def test_known_rule_returns_details(self, dev_rules_dir: Path) -> None:
        """Explaining a known rule should return its details."""
        from reporails_cli.interfaces.mcp.tools import explain_tool

        data = explain_tool("CORE:S:0001", rules_paths=[dev_rules_dir])
        assert "error" not in data
        assert "title" in data or "rule_id" in data

    def test_unknown_rule_returns_error(self) -> None:
        """Explaining an unknown rule should return an error."""
        text = _call_tool("explain", {"rule_id": "ZZZZZ999"})
        data = json.loads(text)
        assert "error" in data


# ---------------------------------------------------------------------------
# judge tool
# ---------------------------------------------------------------------------


class TestJudgeTool:
    def test_records_verdicts(self, level2_project: Path) -> None:
        """judge should record verdicts and return count."""
        verdicts = ["CORE:S:0001:CLAUDE.md:pass:File size OK"]
        text = _call_tool(
            "judge",
            {
                "path": str(level2_project),
                "verdicts": verdicts,
            },
        )
        data = json.loads(text)
        assert "recorded" in data
        assert data["recorded"] == 1

    def test_records_multiple_verdicts(self, level2_project: Path) -> None:
        """judge should handle multiple verdicts."""
        verdicts = [
            "CORE:S:0001:CLAUDE.md:pass:File size OK",
            "CORE:C:0002:CLAUDE.md:fail:Missing section",
        ]
        text = _call_tool(
            "judge",
            {
                "path": str(level2_project),
                "verdicts": verdicts,
            },
        )
        data = json.loads(text)
        assert data["recorded"] == 2

    def test_coordinate_rule_id(self, level2_project: Path) -> None:
        """Coordinate-format rule IDs (CORE:S:0001) should be parsed correctly."""
        verdicts = ["CORE:S:0001:CLAUDE.md:pass:Criteria met"]
        text = _call_tool(
            "judge",
            {
                "path": str(level2_project),
                "verdicts": verdicts,
            },
        )
        data = json.loads(text)
        assert data["recorded"] == 1

    def test_persists_to_cache(self, level2_project: Path) -> None:
        """Verdicts should be persisted in the judgment cache file."""
        from reporails_cli.core.cache import ProjectCache

        verdicts = ["CORE:S:0001:CLAUDE.md:pass:Looks good"]
        _call_tool(
            "judge",
            {
                "path": str(level2_project),
                "verdicts": verdicts,
            },
        )

        cache = ProjectCache(level2_project)
        cache_data = cache.load_judgment_cache()
        judgments = cache_data.get("judgments", {})
        assert "CLAUDE.md" in judgments
        assert "CORE:S:0001" in judgments["CLAUDE.md"].get("results", {})

    def test_empty_verdicts_returns_error(self) -> None:
        """Empty verdicts list should return an error."""
        text = _call_tool("judge", {"path": ".", "verdicts": []})
        data = json.loads(text)
        assert "error" in data

    def test_no_verdicts_key_returns_error(self) -> None:
        """Missing verdicts argument should return an error."""
        text = _call_tool("judge", {"path": "."})
        data = json.loads(text)
        assert "error" in data

    def test_invalid_verdict_format_records_zero(self, level2_project: Path) -> None:
        """Malformed verdict strings should not be recorded."""
        verdicts = ["garbage"]
        text = _call_tool(
            "judge",
            {
                "path": str(level2_project),
                "verdicts": verdicts,
            },
        )
        data = json.loads(text)
        assert data["recorded"] == 0

    def test_nonexistent_file_in_verdict_records_zero(self, level2_project: Path) -> None:
        """Verdict referencing a nonexistent file should not be recorded."""
        verdicts = ["CORE:S:0001:no-such-file.md:pass:OK"]
        text = _call_tool(
            "judge",
            {
                "path": str(level2_project),
                "verdicts": verdicts,
            },
        )
        data = json.loads(text)
        assert data["recorded"] == 0

    def test_path_traversal_blocked(self, tmp_path: Path) -> None:
        """Verdicts referencing files outside the project must be rejected."""
        project = tmp_path / "project"
        sibling = tmp_path / "sibling"
        project.mkdir()
        sibling.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")
        (sibling / "secrets.md").write_text("API_KEY=sk-secret\n")

        text = _call_tool(
            "judge",
            {
                "path": str(project),
                "verdicts": ["CORE:S:0001:../sibling/secrets.md:pass:Should be blocked"],
            },
        )
        data = json.loads(text)
        assert data["recorded"] == 0

    def test_invalid_verdict_value_rejected(self, level2_project: Path) -> None:
        """Verdict must be 'pass' or 'fail'; other values are rejected."""
        verdicts = ["CORE:S:0001:CLAUDE.md:maybe:unsure"]
        text = _call_tool(
            "judge",
            {
                "path": str(level2_project),
                "verdicts": verdicts,
            },
        )
        data = json.loads(text)
        assert data["recorded"] == 0


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------


class TestUnknownTool:
    def test_returns_error(self) -> None:
        """Unknown tool name should return error JSON."""
        text = _call_tool("nonexistent_tool", {})
        data = json.loads(text)
        assert "error" in data
        assert "nonexistent_tool" in data["error"]


# ---------------------------------------------------------------------------
# Circuit breaker — content-aware mtime tracking
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    """Circuit breaker uses content-aware mtime tracking.

    Files unchanged between calls increment consecutive_unchanged.
    Files changed between calls reset consecutive_unchanged.
    """

    def _reset_states(self) -> None:
        from reporails_cli.interfaces.mcp import server

        server._validate_states.clear()

    def setup_method(self) -> None:
        self._reset_states()

    def teardown_method(self) -> None:
        self._reset_states()

    @requires_rules
    def test_first_call_succeeds(self, level2_project: Path) -> None:
        """First validate call should return normal JSON results."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "error" not in data
        assert "score" in data

    @requires_rules
    def test_second_call_succeeds(self, level2_project: Path) -> None:
        """Second validate call (unchanged files) should still succeed."""
        _call_tool("validate", {"path": str(level2_project)})
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "error" not in data
        assert "score" in data

    @requires_rules
    def test_third_unchanged_triggers_breaker(self, level2_project: Path) -> None:
        """Third call without file changes must trigger circuit breaker."""
        _call_tool("validate", {"path": str(level2_project)})
        _call_tool("validate", {"path": str(level2_project)})
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert data.get("error") == "circuit_breaker"

    @requires_rules
    def test_edit_between_calls_resets_breaker(self, level2_project: Path) -> None:
        """Editing a file between validate calls should reset the breaker."""
        _call_tool("validate", {"path": str(level2_project)})
        _call_tool("validate", {"path": str(level2_project)})
        # Edit the instruction file to change mtime
        claude_md = level2_project / "CLAUDE.md"
        claude_md.write_text(claude_md.read_text() + "\n## New Section\n")
        # Third call should NOT trigger breaker because file changed
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "error" not in data
        assert "score" in data

    @requires_rules
    def test_breaker_message_says_do_not_call_again(self, level2_project: Path) -> None:
        """Breaker message must instruct the LLM to stop calling validate."""
        _call_tool("validate", {"path": str(level2_project)})
        _call_tool("validate", {"path": str(level2_project)})
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "DO NOT call validate again" in data.get("message", "")

    @requires_rules
    def test_different_paths_independent(self, level2_project: Path, tmp_path: Path) -> None:
        """Circuit breaker states are per-path, not global."""
        other = tmp_path / "other"
        other.mkdir()
        (other / "CLAUDE.md").write_text("# Other project\n")
        (other / ".reporails").mkdir()

        # Call level2_project twice (at threshold)
        _call_tool("validate", {"path": str(level2_project)})
        _call_tool("validate", {"path": str(level2_project)})

        # Call other path — should NOT trigger breaker
        text = _call_tool("validate", {"path": str(other)})
        data = json.loads(text)
        assert "error" not in data or data.get("error") != "circuit_breaker"

    @requires_rules
    def test_fourth_unchanged_still_blocked(self, level2_project: Path) -> None:
        """Calls beyond the threshold must all be blocked."""
        for _ in range(3):
            _call_tool("validate", {"path": str(level2_project)})
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert data.get("error") == "circuit_breaker"

    @requires_rules
    def test_absolute_ceiling(self, level2_project: Path) -> None:
        """After MAX_CALLS total calls, breaker triggers regardless of file changes."""
        from reporails_cli.interfaces.mcp import server

        claude_md = level2_project / "CLAUDE.md"
        original = claude_md.read_text()
        # Make MAX_CALLS calls, editing file each time to avoid unchanged breaker
        for i in range(server._MAX_CALLS):
            claude_md.write_text(original + f"\n## Edit {i}\n")
            _call_tool("validate", {"path": str(level2_project)})
        # Next call should be blocked by absolute ceiling
        claude_md.write_text(original + "\n## Final\n")
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert data.get("error") == "circuit_breaker"


# ---------------------------------------------------------------------------
# Tool helpers (tools.py) — direct sync tests
# ---------------------------------------------------------------------------


class TestJudgeToolHelper:
    """Test the judge_tool helper function directly."""

    def test_returns_recorded_count_and_details(self, level2_project: Path) -> None:
        from reporails_cli.interfaces.mcp.tools import judge_tool

        result = judge_tool(str(level2_project), ["CORE:S:0001:CLAUDE.md:pass:OK"])
        assert result["recorded"] == 1
        assert result["verdicts"] == [{"rule": "CORE:S:0001", "file": "CLAUDE.md", "verdict": "pass", "reason": "OK"}]

    def test_none_verdicts_returns_error(self) -> None:
        from reporails_cli.interfaces.mcp.tools import judge_tool

        result = judge_tool(".", None)
        assert "error" in result

    def test_missing_path_returns_error(self) -> None:
        from reporails_cli.interfaces.mcp.tools import judge_tool

        result = judge_tool("/tmp/no-such-path-xyz-mcp-test", ["CORE:S:0001:x.md:pass:OK"])
        assert "error" in result


class TestScoreToolHelper:
    """Test the score_tool helper function directly."""

    @requires_rules
    def test_returns_score_dict(self, level2_project: Path) -> None:
        from reporails_cli.interfaces.mcp.tools import score_tool

        result = score_tool(str(level2_project))
        assert "score" in result
        assert "level" in result
        assert "error" not in result

    def test_missing_path_returns_error(self) -> None:
        from reporails_cli.interfaces.mcp.tools import score_tool

        result = score_tool("/tmp/no-such-path-xyz-mcp-test")
        assert "error" in result


# ---------------------------------------------------------------------------
# Verdict parsing — unit-level tests for _parse_verdict_string
# ---------------------------------------------------------------------------


class TestVerdictParsing:
    """Test the verdict string parser directly for edge cases."""

    def _parse(self, s: str) -> tuple[str, str, str, str]:
        from reporails_cli.core.cache import _parse_verdict_string

        return _parse_verdict_string(s)

    def test_short_rule_id(self) -> None:
        assert self._parse("S1:CLAUDE.md:pass:OK") == ("S1", "CLAUDE.md", "pass", "OK")

    def test_short_rule_id_fail(self) -> None:
        assert self._parse("C2:CLAUDE.md:fail:Missing") == ("C2", "CLAUDE.md", "fail", "Missing")

    def test_coordinate_rule_id(self) -> None:
        assert self._parse("CORE:S:0001:CLAUDE.md:pass:Good") == ("CORE:S:0001", "CLAUDE.md", "pass", "Good")

    def test_coordinate_rule_id_fail(self) -> None:
        assert self._parse("AILS:C:0002:.claude/rules/foo.md:fail:Bad") == (
            "AILS:C:0002",
            ".claude/rules/foo.md",
            "fail",
            "Bad",
        )

    def test_short_with_line_number(self) -> None:
        """Line number in location must not be confused with verdict."""
        assert self._parse("S1:CLAUDE.md:42:pass:Has line") == ("S1", "CLAUDE.md:42", "pass", "Has line")

    def test_coordinate_with_line_number(self) -> None:
        """Coordinate ID + line number in location must parse correctly."""
        assert self._parse("CORE:S:0001:CLAUDE.md:42:pass:Has line") == (
            "CORE:S:0001",
            "CLAUDE.md:42",
            "pass",
            "Has line",
        )

    def test_colons_in_reason(self) -> None:
        """Colons in the reason field should be preserved."""
        assert self._parse("S1:CLAUDE.md:pass:reason:with:colons") == ("S1", "CLAUDE.md", "pass", "reason:with:colons")

    def test_empty_string(self) -> None:
        assert self._parse("") == ("", "", "", "")

    def test_garbage(self) -> None:
        assert self._parse("garbage") == ("", "", "", "")

    def test_just_colons(self) -> None:
        assert self._parse(":::") == ("", "", "", "")

    def test_invalid_verdict_value(self) -> None:
        """Verdict must be 'pass' or 'fail'."""
        assert self._parse("S1:CLAUDE.md:maybe:unsure") == ("", "", "", "")

    def test_no_location(self) -> None:
        """Missing location should return empty."""
        _rule_id, location, _verdict, _reason = self._parse("S1::pass:no loc")
        # location is empty string, which means downstream rejects it
        assert location == ""


# ---------------------------------------------------------------------------
# ScanDelta — corrupted cache resilience
# ---------------------------------------------------------------------------


class TestScanDeltaResilience:
    """ScanDelta.compute must not crash on corrupted analytics cache."""

    def _compute(self, prev_level: str) -> Any:
        from reporails_cli.core.models import ScanDelta

        class FakePrev:
            score = 5.0
            violations_count = 2

        FakePrev.level = prev_level  # type: ignore[attr-defined]
        return ScanDelta.compute(5.0, "L3", 2, FakePrev())  # type: ignore[arg-type]

    def test_normal_level(self) -> None:
        d = self._compute("L2")
        assert d.level_improved is True

    def test_truncated_level(self) -> None:
        """'L' with no digit must not crash."""
        d = self._compute("L")
        assert d is not None  # No IndexError

    def test_empty_level(self) -> None:
        d = self._compute("")
        assert d is not None

    def test_garbage_level(self) -> None:
        d = self._compute("garbage")
        assert d is not None


# ---------------------------------------------------------------------------
# Cache atomicity
# ---------------------------------------------------------------------------


class TestCacheAtomicity:
    """Judgment cache writes must use atomic temp+rename."""

    def test_write_creates_no_partial_json(self, level2_project: Path) -> None:
        """After caching verdicts, the cache file must be valid JSON."""
        from reporails_cli.interfaces.mcp.tools import judge_tool

        judge_tool(str(level2_project), ["CORE:S:0001:CLAUDE.md:pass:OK"])

        cache_path = level2_project / ".reporails" / ".cache" / "judgment-cache.json"
        assert cache_path.exists()
        data = json.loads(cache_path.read_text())
        assert "version" in data
        assert "judgments" in data

    def test_no_temp_file_left_behind(self, level2_project: Path) -> None:
        """Atomic write must not leave .tmp files after completion."""
        from reporails_cli.interfaces.mcp.tools import judge_tool

        judge_tool(str(level2_project), ["CORE:S:0001:CLAUDE.md:pass:OK"])

        cache_dir = level2_project / ".reporails" / ".cache"
        tmp_files = list(cache_dir.glob("*.tmp"))
        assert tmp_files == []
