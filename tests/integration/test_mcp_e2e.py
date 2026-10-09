"""End-to-end MCP tool tests — exercise all tools through the server dispatch layer.

Covers the trimmed 0.5.11 surface:
  - Tool listing: validate / preflight / explain present (no score, no heal)
  - validate: returns JSON with findings, tier, per-finding category, surface category_breakdown
  - preflight: returns workflow-ordered rules + Pass / Fail blocks
  - explain: returns rule details or error for unknown rules
  - Circuit breaker: content-aware mtime tracking (safety net for runaway loops)
  - Unknown tool: returns error
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Skip markers
# ---------------------------------------------------------------------------

_has_onnx_model = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
).exists()
requires_model = pytest.mark.skipif(not _has_onnx_model, reason="Bundled ONNX model not available")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rules_installed() -> bool:
    from reporails_cli.core.platform.config.bootstrap import get_rules_path

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


def _bounded_reply(path: Path) -> dict[str, Any]:
    """The bounded `validate` payload as data: a reply with a `preservation` block is served as
    the text view, so the wiring tests read the payload the view is rendered from."""
    from reporails_cli.interfaces.mcp.server import _run_validate

    return _run_async(_run_validate(str(path), False))


# ---------------------------------------------------------------------------
# Structured output (mcp 2.x) — validate returns structuredContent, not just text
# ---------------------------------------------------------------------------


class TestStructuredOutput:
    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_validate_returns_structured_content(self, monkeypatch, tmp_path: Path) -> None:
        """A validate call returns the payload as structuredContent (not only a JSON string)."""
        from reporails_cli.interfaces.mcp import server

        # Use a unique path so the circuit-breaker memoization never pollutes another
        # test keyed on the shared "." cwd.
        server._validate_states.clear()
        payload = {
            "level": "L2",
            "tier": "free",
            "stats": {"score": 7.4},
            "files": {"CLAUDE.md": {"count": 1, "findings": [{"rule": "CORE:C:0001", "line": 1}]}},
        }
        monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: (dict(payload), None, None))

        result = _run_async(server.server.call_tool("validate", {"path": str(tmp_path)}))

        assert result.is_error is False
        assert isinstance(result.structured_content, dict)
        assert result.structured_content.get("level") == "L2"
        assert result.structured_content.get("tier") == "free"
        # Back-compat text mirror is present AND compact (no pretty-print indent) — the token
        # economy the compact `_result` wrapper exists for: the SDK's default pretty mirror
        # duplicated the payload. Reddens if the wrapper regresses to a plain dict return.
        assert result.content and result.content[0].text
        assert "\n  " not in result.content[0].text

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_all_tools_are_read_only(self) -> None:
        """All three tools carry the read-only annotation for clients that read hints."""
        from reporails_cli.interfaces.mcp.server import list_tools

        tools = {t.name: t for t in _run_async(list_tools())}
        for name in ("validate", "remedy_brief", "preflight", "explain"):
            assert tools[name].annotations is not None
            assert tools[name].annotations.read_only_hint is True


# ---------------------------------------------------------------------------
# Tool listing
# ---------------------------------------------------------------------------


class TestListTools:
    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_all_tools_present(self) -> None:
        """list_tools should return the current surface: validate, remedy_brief, heal_apply, preflight, explain."""
        from reporails_cli.interfaces.mcp.server import list_tools

        tools = _run_async(list_tools())
        names = {t.name for t in tools}
        assert names == {"validate", "remedy_brief", "heal_apply", "preflight", "explain"}

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_validate_tool_path_optional(self) -> None:
        """validate tool should not require path (has default)."""
        from reporails_cli.interfaces.mcp.server import list_tools

        tools = _run_async(list_tools())
        validate = next(t for t in tools if t.name == "validate")
        assert "required" not in validate.input_schema

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_validate_description_does_not_promise_a_retired_compliance_band(self) -> None:
        """The `validate` description promised a `compliance band` in its JSON — no
        such field reaches the JSON/MCP envelope (`formatters/json.py`'s `quality` key is a
        bare float score); the claim is stale."""
        from reporails_cli.interfaces.mcp.server import list_tools

        tools = _run_async(list_tools())
        validate = next(t for t in tools if t.name == "validate")
        assert "compliance band" not in validate.description.lower()

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_server_version_is_the_package_version(self) -> None:
        """`initialize`'s `serverInfo.version` was always empty — `MCPServer("ails", ...)`
        never passed its own `version`, and the SDK defaults it to `""`. A caller has no way to
        tell which server build it is talking to without it."""
        from reporails_cli import __version__
        from reporails_cli.interfaces.mcp.server import server

        assert server.version == __version__
        assert server.version != ""


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
    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_returns_valid_json(self, level2_project: Path) -> None:
        """validate must return parseable JSON."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)  # Must not raise
        assert isinstance(data, dict)

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_json_has_files_and_stats(self, level2_project: Path) -> None:
        """validate JSON must contain files and stats keys."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "files" in data
        assert "stats" in data

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_json_has_violations_grouped_by_file(self, level2_project: Path) -> None:
        """validate JSON must contain violations as a dict grouped by file."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        if "violations" in data:
            assert isinstance(data["violations"], dict)
            for file_key, entries in data["violations"].items():
                assert isinstance(file_key, str)
                assert isinstance(entries, list)
                for entry in entries:
                    assert isinstance(entry, list)
                    assert len(entry) == 4  # [rule_id, line_ref, severity, message]

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_json_has_offline_flag(self, level2_project: Path) -> None:
        """validate JSON must contain offline flag."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "offline" in data

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_no_shell_out_guidance(self, level2_project: Path) -> None:
        """REGRESSION: validate must never tell the LLM to shell out."""
        text = _call_tool("validate", {"path": str(level2_project)})
        for pattern in _SHELL_OUT_PATTERNS:
            assert pattern not in text, f"Shell-out pattern {pattern!r} found in validate response"

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_missing_path_returns_error_json(self) -> None:
        """Non-existent path should return JSON error."""
        text = _call_tool("validate", {"path": "/tmp/no-such-path-xyz-mcp-test"})
        data = json.loads(text)
        assert "error" in data

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_missing_rules_folder_names_what_is_missing_and_what_to_do(self) -> None:
        """When the rules folder holds no `core` rules, validate returns a structured
        `needs_install` payload that names the folder and says to reinstall the package or fix
        `framework_path`, and does not point at a rules download."""
        with patch("reporails_cli.interfaces.mcp.tools.is_initialized", return_value=False):
            text = _call_tool("validate", {"path": "."})
        data = json.loads(text)
        assert data.get("needs_install") is True
        assert "reinstall reporails-cli" in data["message"]
        assert "framework_path" in data["message"]
        assert "ails install" not in text
        assert "download" not in text

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_runtime_error_returns_error_json(self, level2_project: Path) -> None:
        """RuntimeError from _run_pipeline must return JSON error, not crash."""
        with (
            patch("reporails_cli.interfaces.mcp.tools.is_initialized", return_value=True),
            patch(
                "reporails_cli.interfaces.mcp.tools._run_pipeline",
                side_effect=RuntimeError("Unsupported operating system"),
            ),
        ):
            text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "error" in data
        assert data["error"] == "Unsupported operating system"


# ---------------------------------------------------------------------------
# preflight tool
# ---------------------------------------------------------------------------


def _skills_project(root: Path) -> Path:
    """A Claude project with a root file, two skills and an agent."""
    (root / "CLAUDE.md").write_text("# Project\n\nRun `pytest` before committing.\n")
    for name in ("backlog", "release"):
        skill = root / ".claude" / "skills" / name / "SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text(f"# {name}\n\nUse this skill for {name} work.\n")
    agent = root / ".claude" / "agents" / "reviewer.md"
    agent.parent.mkdir(parents=True)
    agent.write_text("# Reviewer\n\nReview the diff.\n")
    return root


def _location(order: int, kind: str, element: str, files: list[str]) -> dict:
    return {
        "order": order,
        "element": element,
        "kind": kind,
        "loading": "",
        "files": files,
        "importance": "conditional",
        "findings": [],
        "relations": [],
    }


class TestValidateTargets:
    """`validate(targets=[...])` diagnoses the whole project, then keeps only the locations
    holding a targeted file, re-numbered from 1; `remedy_brief` reads that view back with the
    same targets, and the whole-project view keeps its own numbering."""

    _PAYLOAD: ClassVar[dict] = {
        "tier": "pro",
        "stats": {"score": 6.0},
        "files": {"CLAUDE.md": {"count": 1, "findings": []}},
        "workflow": {
            "summary": "4 locations to rewrite, by kind: 1 main, 1 agents, 2 skills.",
            "escape": "e",
            "listed": [{"rule": "CORE:C:0005", "reason": "no_remedy", "count": 1, "why": ""}],
            "locations": [
                _location(1, "main", "CLAUDE.md", ["CLAUDE.md"]),
                _location(2, "agents", "the `reviewer` agent", [".claude/agents/reviewer.md"]),
                _location(3, "skills", "the `backlog` skill", [".claude/skills/backlog/SKILL.md"]),
                _location(4, "skills", "the `release` skill", [".claude/skills/release/SKILL.md"]),
            ],
        },
    }

    @pytest.fixture
    def project(self, monkeypatch, tmp_path: Path) -> Path:
        from reporails_cli.interfaces.mcp import server

        server._validate_states.clear()
        monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: (self._PAYLOAD, None, None))
        return _skills_project(tmp_path)

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    @requires_rules
    def test_a_capability_target_keeps_only_its_locations(self, project: Path) -> None:
        from reporails_cli.interfaces.mcp import server

        data = _run_async(server._run_validate(str(project), True, ["skills"]))
        wf = data["workflow"]
        assert [(loc["order"], loc["element"]) for loc in wf["locations"]] == [
            (1, "the `backlog` skill"),
            (2, "the `release` skill"),
        ]
        assert wf["targets"] == {"tokens": ["skills"], "locations": 2, "of": 4}
        assert wf["listed"] == self._PAYLOAD["workflow"]["listed"]
        assert data["stats"] == self._PAYLOAD["stats"]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    @requires_rules
    def test_one_element_and_a_typed_word_read_like_ails_check(self, project: Path) -> None:
        from reporails_cli.interfaces.mcp import server

        one = _run_async(server._run_validate(str(project), True, ["skill:release"]))
        assert [loc["element"] for loc in one["workflow"]["locations"]] == ["the `release` skill"]
        path = _run_async(server._run_validate(str(project), True, [".claude/agents"]))
        assert [loc["element"] for loc in path["workflow"]["locations"]] == ["the `reviewer` agent"]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    @requires_rules
    @pytest.mark.requires_model
    def test_remedy_brief_reads_the_targeted_view_and_the_whole_view_keeps_its_numbering(self, project: Path) -> None:
        from reporails_cli.interfaces.mcp import server

        _run_async(server._run_validate(str(project), True, ["skills"]))
        brief = server._serve_remedy_brief(str(project), 1, ["skills"], has_guide=True)
        assert brief["location"]["element"] == "the `backlog` skill"
        assert server._serve_remedy_brief(str(project), 1, has_guide=True)["error"] == "no_workflow"
        _run_async(server._run_validate(str(project), True))
        assert server._serve_remedy_brief(str(project), 1, has_guide=True)["location"]["element"] == "CLAUDE.md"
        assert (
            server._serve_remedy_brief(str(project), 1, ["skills"], has_guide=True)["location"]["element"]
            == "the `backlog` skill"
        )

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    @requires_rules
    def test_a_target_that_names_nothing_is_a_structured_error(self, project: Path) -> None:
        from reporails_cli.interfaces.mcp import server

        missing = _run_async(server._run_validate(str(project), True, ["skills:nope"]))
        assert missing["error"] == "target_not_found"
        assert "nope" in missing["message"]


class TestPreflightTool:
    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_returns_workflow_ordered_rules(self) -> None:
        """preflight returns rules sorted by category in workflow order."""
        text = _call_tool("preflight", {"capability": "skill"})
        data = json.loads(text)
        assert data.get("capability") == "skills"
        assert "rules" in data
        assert isinstance(data["rules"], list)
        # Sanity: at least one rule, and each has the expected envelope shape
        if data["rules"]:
            first = data["rules"][0]
            assert "id" in first
            assert "title" in first
            assert "category" in first
            assert "severity" in first

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_empty_capability_returns_error(self) -> None:
        """Missing capability surfaces as a structured error, not a crash."""
        text = _call_tool("preflight", {"capability": ""})
        data = json.loads(text)
        assert "error" in data

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_pass_fail_examples_attached(self) -> None:
        """Rules with rule.md Pass / Fail sections surface their bodies inline."""
        text = _call_tool("preflight", {"capability": "skill"})
        data = json.loads(text)
        any_with_pass = any("pass_example" in r for r in data.get("rules", []))
        any_with_fail = any("fail_example" in r for r in data.get("rules", []))
        # Whichever exists in the corpus surfaces — at least one direction
        # should be populated when the framework is installed and rules carry
        # Pass / Fail blocks (which is the corpus norm).
        assert any_with_pass or any_with_fail


# ---------------------------------------------------------------------------
# explain tool
# ---------------------------------------------------------------------------


class TestExplainTool:
    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_known_rule_returns_details(self, dev_rules_dir: Path) -> None:
        """Explaining a known rule should return readable text with rule ID and title."""
        from reporails_cli.interfaces.mcp.rule_tools import explain_tool

        result = explain_tool("CORE:S:0002", rules_paths=[dev_rules_dir])
        assert isinstance(result, str)
        assert "CORE:S:0002" in result
        assert "Section Headers Present" in result

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_unknown_rule_returns_error(self) -> None:
        """Explaining an unknown rule should return an error."""
        text = _call_tool("explain", {"rule_id": "ZZZZZ999"})
        data = json.loads(text)
        assert "error" in data


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------


class TestUnknownTool:
    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_returns_error(self) -> None:
        """Unknown tool name should return error JSON."""
        text = _call_tool("nonexistent_tool", {})
        data = json.loads(text)
        assert "error" in data
        assert "nonexistent_tool" in data["error"]


class TestUnknownArgument:
    """The SDK's generated argument model ignores an extra key rather than rejecting it,
    so a typo'd or retired argument was silently dropped with no signal at all."""

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_an_unknown_argument_is_rejected_not_silently_dropped(self) -> None:
        text = _call_tool("preflight", {"capability": "skills", "bogus_extra_arg": "x"})
        data = json.loads(text)
        assert "error" in data
        assert "bogus_extra_arg" in data["error"]

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_a_known_argument_set_is_unaffected(self) -> None:
        text = _call_tool("preflight", {"capability": "skills"})
        data = json.loads(text)
        assert "error" not in data

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_rejected_at_the_real_dispatch_seam_not_only_the_shim(self) -> None:
        """The check binds on `server.call_tool` itself (`_StrictArgsMCPServer`), the same
        method the real stdio dispatch (`_handle_call_tool`) calls — not only this module's
        own `call_tool` convenience shim."""
        from mcp.server.mcpserver.exceptions import ToolError

        from reporails_cli.interfaces.mcp.server import server

        with pytest.raises(ToolError, match="bogus_extra_arg"):
            _run_async(server.call_tool("preflight", {"capability": "skills", "bogus_extra_arg": "x"}))


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

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_first_call_succeeds(self, level2_project: Path) -> None:
        """First validate call should return normal JSON results."""
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "error" not in data
        assert "files" in data

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_second_call_succeeds(self, level2_project: Path) -> None:
        """Second validate call (unchanged files) should still succeed."""
        _call_tool("validate", {"path": str(level2_project)})
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "error" not in data
        assert "files" in data

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_third_unchanged_triggers_breaker(self, level2_project: Path) -> None:
        """Third call without file changes must trigger circuit breaker."""
        _call_tool("validate", {"path": str(level2_project)})
        _call_tool("validate", {"path": str(level2_project)})
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert data.get("error") == "circuit_breaker"

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
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
        assert "files" in data

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_four_iterations_with_content_changing_each_time_never_trip_the_breaker(self, level2_project: Path) -> None:
        """The rewrite -> validate -> revise -> validate loop an agent runs on one file: up to
        4 validates, the content changing between every one, must never see `circuit_breaker`
        — `_MAX_CALLS = 10` alone already clears 4, and each edit resets `consecutive_unchanged`
        before it could reach `_MAX_UNCHANGED`. A validate with no content change in between
        still counts as unchanged — `test_third_unchanged_triggers_breaker` above pins that
        half of the contract."""
        claude_md = level2_project / "CLAUDE.md"
        original = claude_md.read_text()
        for i in range(4):
            claude_md.write_text(original + f"\n## Revision {i}\n")
            data = json.loads(_call_tool("validate", {"path": str(level2_project)}))
            assert data.get("error") != "circuit_breaker", data
            assert "files" in data

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_breaker_message_says_do_not_call_again(self, level2_project: Path) -> None:
        """Breaker message must instruct the LLM to stop calling validate."""
        _call_tool("validate", {"path": str(level2_project)})
        _call_tool("validate", {"path": str(level2_project)})
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert "DO NOT call validate again" in data.get("message", "")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_different_paths_independent(self, level2_project: Path, tmp_path: Path) -> None:
        """Circuit breaker states are per-path, not global."""
        other = tmp_path / "other"
        other.mkdir()
        (other / "CLAUDE.md").write_text("# Other project\n")
        (other / ".ails").mkdir()

        # Call level2_project twice (at threshold)
        _call_tool("validate", {"path": str(level2_project)})
        _call_tool("validate", {"path": str(level2_project)})

        # Call other path — should NOT trigger breaker
        text = _call_tool("validate", {"path": str(other)})
        data = json.loads(text)
        assert "error" not in data or data.get("error") != "circuit_breaker"

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_fourth_unchanged_still_blocked(self, level2_project: Path) -> None:
        """Calls beyond the threshold must all be blocked."""
        for _ in range(3):
            _call_tool("validate", {"path": str(level2_project)})
        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert data.get("error") == "circuit_breaker"

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
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

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @pytest.mark.requires_model
    def test_eleven_validates_across_two_rounds_survive_a_brief_between_them(self, monkeypatch, tmp_path: Path) -> None:
        """A heal pass makes up to 6 `validate` calls; `_MAX_CALLS = 10` used to trip the
        breaker during a "continue" (second-tier) pass. A served `remedy_brief` between rounds
        resets `call_count` — the agent is still working the loop — so 11 validates across two
        rounds, with a brief and a file edit between them, must not trip."""
        from reporails_cli.interfaces.mcp import server

        payload = {
            "tier": "pro",
            "stats": {},
            "files": {"CLAUDE.md": {"count": 1, "findings": []}},
            "workflow": {
                "summary": "s",
                "escape": "e",
                "locations": [
                    {
                        "order": 1,
                        "element": "CLAUDE.md",
                        "kind": "main",
                        "loading": "session_start",
                        "files": ["CLAUDE.md"],
                        "importance": "gate_mover",
                        "findings": [],
                        "relations": [],
                    }
                ],
            },
        }
        monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: (payload, None, None))
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Project\n")

        def validate() -> dict:
            return _run_async(server._run_validate(str(tmp_path), False))

        # Round 1: 6 validate calls, each with a file edit so no unchanged-repeat trips first.
        for i in range(6):
            claude_md.write_text(f"# Project\n\nedit {i}\n")
            data = validate()
            assert data.get("error") != "circuit_breaker", data

        # A served remedy_brief resets call_count for this path before the next tier's round.
        brief = server._serve_remedy_brief(str(tmp_path), 1, has_guide=True)
        assert "error" not in brief, brief

        # Round 2: 5 more validate calls (11 total across the run) must not trip.
        for i in range(5):
            claude_md.write_text(f"# Project\n\nround2 edit {i}\n")
            data = validate()
            assert data.get("error") != "circuit_breaker", data


# ---------------------------------------------------------------------------
# `full=true` is memoized and excluded from the circuit breaker
# ---------------------------------------------------------------------------


class TestFullMemoization:
    """`validate` → `validate(full=true)` → `validate` must not trip the breaker, and the
    underlying pipeline must run only once across the sequence — the bounded response's own
    hint tells the caller to make exactly the `full=true` follow-up call, so it must not read
    as "no progress" or force a second server lint."""

    def _reset_states(self) -> None:
        from reporails_cli.interfaces.mcp import server

        server._validate_states.clear()

    def setup_method(self) -> None:
        self._reset_states()

    def teardown_method(self) -> None:
        self._reset_states()

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_full_followup_is_memoized_and_does_not_trip_the_breaker(self, level2_project: Path, monkeypatch) -> None:
        from reporails_cli.interfaces.mcp import server

        calls = {"n": 0}
        real_run_pipeline_for_path = server.run_pipeline_for_path

        def counting_run_pipeline_for_path(path: str, full: bool = False):
            calls["n"] += 1
            return real_run_pipeline_for_path(path, full)

        monkeypatch.setattr(server, "run_pipeline_for_path", counting_run_pipeline_for_path)

        text1 = _call_tool("validate", {"path": str(level2_project)})
        text2 = _call_tool("validate", {"path": str(level2_project), "full": True})
        text3 = _call_tool("validate", {"path": str(level2_project)})

        for text in (text1, text2, text3):
            data = json.loads(text)
            assert data.get("error") != "circuit_breaker", data

        assert calls["n"] == 1, f"the pipeline must run once across the sequence, ran {calls['n']} times"

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_full_followup_returns_every_finding_the_bounded_call_withheld(self, level2_project: Path) -> None:
        bounded_text = _call_tool("validate", {"path": str(level2_project)})
        full_text = _call_tool("validate", {"path": str(level2_project), "full": True})

        bounded = json.loads(bounded_text)
        full = json.loads(full_text)
        assert "truncated" not in full
        assert full.get("stats") == bounded.get("stats")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_edit_after_full_followup_still_resets_the_breaker(self, level2_project: Path) -> None:
        """A content change after the `full=true` memo must still invalidate it and count
        as a fresh baseline — the exemption is for the same-content follow-up only."""
        _call_tool("validate", {"path": str(level2_project)})
        _call_tool("validate", {"path": str(level2_project), "full": True})
        claude_md = level2_project / "CLAUDE.md"
        claude_md.write_text(claude_md.read_text() + "\n## New Section\n")

        text = _call_tool("validate", {"path": str(level2_project)})
        data = json.loads(text)
        assert data.get("error") != "circuit_breaker"


# ---------------------------------------------------------------------------
# Tool helpers (tools.py) — direct sync tests
# ---------------------------------------------------------------------------


class TestPreflightToolHelper:
    """Test the preflight_tool helper function directly."""

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_returns_rules_for_capability(self) -> None:
        from reporails_cli.interfaces.mcp.rule_tools import preflight_tool

        result = preflight_tool("skill")
        assert result.get("capability") == "skills"
        assert "rules" in result
        assert "error" not in result

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    @pytest.mark.parametrize(
        ("word", "key", "rule_id"), [("agent", "agents", "CORE:S:0057"), ("rule", "rules", "CORE:S:0006")]
    )
    def test_a_typed_word_returns_its_file_type_s_own_rules(self, word: str, key: str, rule_id: str) -> None:
        """`agent` / `rule` name the config file types `agents` / `rules`: the reply carries their
        own rules on top of the universal ones, never the universal rules alone. The universal
        count is measured directly (`preflight("no-such-type")` no longer stands in
        for it — that capability now errors as `unknown_capability`, not a plausible universal set)."""
        from reporails_cli.core.platform.adapters.rules_query import load_all_rules
        from reporails_cli.interfaces.mcp.rule_tools import preflight_tool

        universal = sum(1 for r in load_all_rules() if r.match is None or r.match.type is None)
        result = preflight_tool(word)
        assert result["capability"] == key
        assert result["count"] > universal
        assert rule_id in {r["id"] for r in result["rules"]}

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_empty_capability_returns_error(self) -> None:
        from reporails_cli.interfaces.mcp.rule_tools import preflight_tool

        result = preflight_tool("")
        assert "error" in result

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_unknown_capability_names_itself_and_the_known_list(self) -> None:
        """An unknown capability used to fall through to the universal-rule branch and
        return a plausible-looking generic rule set. It must instead name the typo."""
        from reporails_cli.interfaces.mcp.rule_tools import preflight_tool

        result = preflight_tool("no-such-type")
        assert result["error"] == "unknown_capability"
        assert result["capability"] == "no-such-type"
        assert "skills" in result["known_capabilities"]

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    @requires_rules
    def test_unknown_agent_names_itself_and_the_known_list(self) -> None:
        """An unknown `agent` used to fall through the same way. It must name the typo,
        mirroring the CLI's own `_validate_agent` shape."""
        from reporails_cli.interfaces.mcp.rule_tools import preflight_tool

        result = preflight_tool("skills", agent="no-such-agent")
        assert result["error"] == "Unknown agent: no-such-agent"
        assert "claude" in result["known_agents"]


class TestDisplayScoreHelper:
    """`_display_score` must pick the `per_file_analysis` entry whose normalized path IS
    the target file, never entry 0 blindly — `generic_scanning` can join `@`-imported files
    into the scored set ahead of the target."""

    @staticmethod
    def _fa(file: str, score: float | None) -> Any:
        from reporails_cli.core.platform.dto.diagnostics import FileAnalysis

        return FileAnalysis(file=file, display_score=score)

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_picks_the_target_s_own_entry_even_when_an_imported_file_is_listed_first(self, tmp_path: Path) -> None:
        from reporails_cli.interfaces.mcp.tools import _display_score

        target = tmp_path / "CLAUDE.md"
        target.write_text("# Project\n")
        imported = tmp_path / "imported.md"
        imported.write_text("# Imported\n")

        result = SimpleNamespace(
            per_file_analysis=(self._fa(str(imported), 9.9), self._fa(str(target), 4.2)),
            quality=None,
        )

        assert _display_score(result, target, tmp_path) == 4.2

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_falls_back_to_quality_only_when_the_target_has_no_entry(self, tmp_path: Path) -> None:
        from reporails_cli.interfaces.mcp.tools import _display_score

        target = tmp_path / "CLAUDE.md"
        target.write_text("# Project\n")
        other = tmp_path / "other.md"

        result = SimpleNamespace(
            per_file_analysis=(self._fa(str(other), 9.9),),
            quality=SimpleNamespace(display_score=6.5),
        )

        assert _display_score(result, target, tmp_path) == 6.5


# ---------------------------------------------------------------------------
# Verdict parsing — unit-level tests for _parse_verdict_string
# ---------------------------------------------------------------------------


class TestVerdictParsing:
    """Test the verdict string parser directly for edge cases."""

    def _parse(self, s: str) -> tuple[str, str, str, str]:
        from reporails_cli.core.cache import _parse_verdict_string

        return _parse_verdict_string(s)

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_short_rule_id(self) -> None:
        assert self._parse("S1:CLAUDE.md:pass:OK") == ("S1", "CLAUDE.md", "pass", "OK")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_short_rule_id_fail(self) -> None:
        assert self._parse("C2:CLAUDE.md:fail:Missing") == ("C2", "CLAUDE.md", "fail", "Missing")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_coordinate_rule_id(self) -> None:
        assert self._parse("CORE:S:0001:CLAUDE.md:pass:Good") == ("CORE:S:0001", "CLAUDE.md", "pass", "Good")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_coordinate_rule_id_fail(self) -> None:
        assert self._parse("AILS:C:0002:.claude/rules/foo.md:fail:Bad") == (
            "AILS:C:0002",
            ".claude/rules/foo.md",
            "fail",
            "Bad",
        )

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_short_with_line_number(self) -> None:
        """Line number in location must not be confused with verdict."""
        assert self._parse("S1:CLAUDE.md:42:pass:Has line") == ("S1", "CLAUDE.md:42", "pass", "Has line")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_coordinate_with_line_number(self) -> None:
        """Coordinate ID + line number in location must parse correctly."""
        assert self._parse("CORE:S:0001:CLAUDE.md:42:pass:Has line") == (
            "CORE:S:0001",
            "CLAUDE.md:42",
            "pass",
            "Has line",
        )

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_colons_in_reason(self) -> None:
        """Colons in the reason field should be preserved."""
        assert self._parse("S1:CLAUDE.md:pass:reason:with:colons") == ("S1", "CLAUDE.md", "pass", "reason:with:colons")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_empty_string(self) -> None:
        assert self._parse("") == ("", "", "", "")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_garbage(self) -> None:
        assert self._parse("garbage") == ("", "", "", "")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_just_colons(self) -> None:
        assert self._parse(":::") == ("", "", "", "")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_invalid_verdict_value(self) -> None:
        """Verdict must be 'pass' or 'fail'."""
        assert self._parse("S1:CLAUDE.md:maybe:unsure") == ("", "", "", "")

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
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
        from reporails_cli.core.platform.dto.results import ScanDelta

        class FakePrev:
            score = 5.0
            violations_count = 2

        FakePrev.level = prev_level  # type: ignore[attr-defined]
        return ScanDelta.compute(5.0, "L3", 2, FakePrev())  # type: ignore[arg-type]

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_normal_level(self) -> None:
        d = self._compute("L2")
        assert d.level_improved is True

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_truncated_level(self) -> None:
        """'L' with no digit must not crash."""
        d = self._compute("L")
        assert d is not None  # No IndexError

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_empty_level(self) -> None:
        d = self._compute("")
        assert d is not None

    @pytest.mark.e2e
    @pytest.mark.subsys_cli_ux
    @pytest.mark.subsys_api
    def test_garbage_level(self) -> None:
        d = self._compute("garbage")
        assert d is not None


# ---------------------------------------------------------------------------
# remedy_brief serves one location's rewrite brief from the last validate's payload
# ---------------------------------------------------------------------------


class TestRemedyBrief:
    """`remedy_brief(path, location)` reads the last `validate(path)`'s stored workflow and
    scan root, resolves the location's files, and returns its rewrite brief — never running
    `validate`'s own pipeline for `path` or moving its circuit-breaker counters."""

    def setup_method(self) -> None:
        from reporails_cli.interfaces.mcp import server

        server._validate_states.clear()

    teardown_method = setup_method

    @staticmethod
    def _payload() -> dict:
        return {
            "tier": "pro",
            "stats": {},
            "files": {"CLAUDE.md": {"count": 1, "findings": []}},
            "workflow": {
                "summary": "s",
                "escape": "e",
                "locations": [
                    {
                        "order": 1,
                        "element": "CLAUDE.md",
                        "kind": "main",
                        "loading": "session_start",
                        "files": ["CLAUDE.md"],
                        "importance": "gate_mover",
                        "findings": [
                            {
                                "rule": "CORE:C:0042",
                                "file": "CLAUDE.md",
                                "line": 3,
                                "pi": 0,
                                "message": "m",
                                "remedy": "r",
                            }
                        ],
                        "relations": [],
                    }
                ],
            },
        }

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_a_brief_before_any_validate_is_a_structured_error(self, tmp_path: Path) -> None:
        data = json.loads(_call_tool("remedy_brief", {"path": str(tmp_path), "location": 1, "has_guide": True}))
        assert data["error"] == "no_workflow"

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_a_brief_for_an_unknown_location_is_a_structured_error(self, monkeypatch, tmp_path: Path) -> None:
        from reporails_cli.interfaces.mcp import server

        monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: (self._payload(), None, None))
        (tmp_path / "CLAUDE.md").write_text("# Project\n")
        _call_tool("validate", {"path": str(tmp_path)})

        data = json.loads(_call_tool("remedy_brief", {"path": str(tmp_path), "location": 9, "has_guide": True}))
        assert data["error"] == "location_not_found"

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    @requires_rules
    def test_a_brief_resets_call_count_but_leaves_consecutive_unchanged(self, monkeypatch, tmp_path: Path) -> None:
        """A served brief resets `call_count` every time (the agent is still working the
        loop); `consecutive_unchanged` — the actual no-progress guard — is untouched."""
        from types import SimpleNamespace

        from reporails_cli.interfaces.mcp import server, tools

        fake_map = SimpleNamespace(atoms=(), files=())
        monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: (self._payload(), None, None))
        monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, fake_map, None))
        (tmp_path / "CLAUDE.md").write_text("# Project\n")
        _call_tool("validate", {"path": str(tmp_path)})
        state_before = server._validate_states[str(tmp_path.resolve())]
        unchanged_before = state_before.consecutive_unchanged

        for _ in range(5):
            reply = json.loads(_call_tool("remedy_brief", {"path": str(tmp_path), "location": 1, "has_guide": True}))
            assert "error" not in reply, reply
            state_after = server._validate_states[str(tmp_path.resolve())]
            assert (state_after.call_count, state_after.consecutive_unchanged) == (0, unchanged_before)

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    @requires_rules
    def test_a_brief_returns_the_location_edits_slots_and_the_preservation_contract(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        from types import SimpleNamespace

        from reporails_cli.interfaces.mcp import server, tools

        fake_map = SimpleNamespace(atoms=(), files=())
        monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: (self._payload(), None, None))
        monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, fake_map, None))
        (tmp_path / "CLAUDE.md").write_text("# Project\n")
        _call_tool("validate", {"path": str(tmp_path)})

        reply = json.loads(_call_tool("remedy_brief", {"path": str(tmp_path), "location": 1, "has_guide": True}))

        assert reply["location"]["order"] == 1 and reply["location"]["kind"] == "main"
        # The 0.6.2 brief carries the exact edits, the slots that need a decision, and the
        # guide per rule; the finding prose and the per-file inventory are gone.
        assert {"edits", "slots", "ops", "guides", "location", "next", "preservation_contract", "refused"} <= set(reply)
        assert "findings" not in reply and "files" not in reply
        assert reply["location"]["root"] == str(tmp_path)
        assert reply["edits"] == [] and reply["slots"] == []
        assert "Keep every instruction" in reply["preservation_contract"]
        assert reply["next"]


# ---------------------------------------------------------------------------
# The preservation check reaches `validate(path=<file>)` for a briefed file
# ---------------------------------------------------------------------------


class TestPreservationWiring:
    """`validate(path=<file>)` on a file `remedy_brief` snapshotted carries a `preservation`
    block on both the bounded and full replies; an unsnapshotted file carries none. The
    matching logic itself (what counts as lost/flipped/detached) is covered by
    `tests/unit/test_preservation.py`; this pins the wiring at the MCP seam."""

    def setup_method(self) -> None:
        from reporails_cli.interfaces.mcp import server, snapshots

        server._validate_states.clear()
        snapshots.clear_snapshots()

    teardown_method = setup_method

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    @requires_model
    @requires_rules
    def test_a_snapshotted_file_carries_preservation_on_both_bounded_and_full_replies(self, tmp_path: Path) -> None:
        from reporails_cli.interfaces.mcp import snapshots, tools

        target = tmp_path / "CLAUDE.md"
        target.write_text("# Project\n\nNever commit secrets.\n")

        bounded_before = _bounded_reply(target)
        assert "preservation" not in bounded_before, "not yet briefed"

        _payload, ruleset_map, score = tools.run_pipeline_for_path(str(target), True)
        snapshots.snapshot_file(target, ruleset_map, score, [])

        bounded_after = _bounded_reply(target)
        assert "preservation" in bounded_after
        assert bounded_after["preservation"]["ok"] is True, "nothing changed since the snapshot"
        assert bounded_after["preservation"]["score_before"] == score

        full = json.loads(_call_tool("validate", {"path": str(target), "full": True}))
        assert "preservation" in full

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    @requires_model
    @requires_rules
    def test_a_renamed_bare_negative_heading_is_reported_on_the_reply(self, tmp_path: Path) -> None:
        from reporails_cli.interfaces.mcp import snapshots, tools

        target = tmp_path / "CLAUDE.md"
        target.write_text("## Don'ts\n\n- Use mock objects in tests.\n- Use test doubles in the test suite.\n")
        _payload, ruleset_map, score = tools.run_pipeline_for_path(str(target), True)
        snapshots.snapshot_file(target, ruleset_map, score, [])

        target.write_text(
            "## Test doubles\n\n- Do not use mock objects in tests.\n- Do not use test doubles in the test suite.\n"
        )
        block = _bounded_reply(target)["preservation"]
        assert block["ok"] is False
        assert block["relabelled_negative_headings"] == [{"line": 1, "text": "## Don'ts"}]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    @requires_model
    @requires_rules
    def test_a_cached_reply_s_preservation_check_does_not_rerun_the_pipeline(self, tmp_path: Path, monkeypatch) -> None:
        """`_with_preservation` on a cache-hit reply (unchanged content, so `validate`
        serves the memoized full payload) used to call `run_pipeline_for_path` a SECOND time —
        an extra mapping + server diagnose — just to get the map/score it needed for the
        preservation compare. It must now reuse what the fresh run already stored."""
        from reporails_cli.interfaces.mcp import server, snapshots, tools

        target = tmp_path / "CLAUDE.md"
        target.write_text("# Project\n\nNever commit secrets.\n")

        _payload, ruleset_map, score = tools.run_pipeline_for_path(str(target), True)
        snapshots.snapshot_file(target, ruleset_map, score, [])

        calls = {"n": 0}
        real_run_pipeline_for_path = server.run_pipeline_for_path

        def counting_run_pipeline_for_path(path: str, full: bool = False):
            calls["n"] += 1
            return real_run_pipeline_for_path(path, full)

        monkeypatch.setattr(server, "run_pipeline_for_path", counting_run_pipeline_for_path)

        first = _bounded_reply(target)
        assert "preservation" in first
        assert calls["n"] == 1, "the first (fresh) validate must run the pipeline exactly once"

        second = _bounded_reply(target)
        assert "preservation" in second
        assert calls["n"] == 1, (
            f"a cached-reply preservation check must reuse the stored map, not re-run the "
            f"pipeline — ran {calls['n']} times across two unchanged validates"
        )


# ---------------------------------------------------------------------------
# `validate(path=<file>)` feedback — the file's remaining findings after a rewrite
# ---------------------------------------------------------------------------


class TestFileFeedback:
    """`feedback.file_feedback` — the pure shaping logic behind `validate(path=<file>)`'s
    `feedback` field, exercised directly against synthetic payload dicts so this stays fast
    and does not depend on a real map/model. The MCP wiring (gated on a snapshotted file, on
    both bounded and full replies) is covered by `TestFeedbackWiring` below."""

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_prefers_workflow_findings_for_the_file_weakest_first(self) -> None:
        from reporails_cli.interfaces.mcp import feedback

        payload = {
            "files": {"CLAUDE.md": {"count": 1, "findings": [{"rule": "Z", "line": 1, "message": "m", "fix": "f"}]}},
            "workflow": {
                "locations": [
                    {
                        "order": 1,
                        "files": ["CLAUDE.md"],
                        "findings": [
                            {
                                "rule": "A",
                                "file": "CLAUDE.md",
                                "line": 3,
                                "pi": 0,
                                "message": "cosmetic issue",
                                "op": "rewrite",
                                "impact_tier": "cosmetic",
                            },
                            {
                                "rule": "B",
                                "file": "CLAUDE.md",
                                "line": 8,
                                "pi": 1,
                                "message": "gate issue",
                                "op": "split",
                                "impact_tier": "gate_mover",
                            },
                            {
                                "rule": "C",
                                "file": "OTHER.md",
                                "line": 1,
                                "pi": 0,
                                "message": "other file",
                                "op": "split",
                                "impact_tier": "gate_mover",
                            },
                        ],
                    }
                ]
            },
        }
        feedback = feedback.file_feedback(payload, Path("/proj/CLAUDE.md"), Path("/proj"))
        assert feedback == [
            {"rule": "B", "line": 8, "message": "gate issue", "op": "split", "impact_tier": "gate_mover"},
            {"rule": "A", "line": 3, "message": "cosmetic issue", "op": "rewrite", "impact_tier": "cosmetic"},
        ]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_falls_back_to_per_file_findings_when_no_workflow_finding_names_the_file(self) -> None:
        from reporails_cli.interfaces.mcp import feedback

        payload = {
            "files": {
                "CLAUDE.md": {
                    "count": 2,
                    "findings": [
                        {"rule": "X", "line": 5, "message": "m1", "fix": "fix1"},
                        {"rule": "Y", "line": 2, "message": "m2"},
                    ],
                }
            },
            "workflow": {"locations": [{"order": 1, "files": ["CLAUDE.md"], "findings": []}]},
        }
        feedback = feedback.file_feedback(payload, Path("/proj/CLAUDE.md"), Path("/proj"))
        # No `impact_tier`, so weight ties and the line number decides.
        assert feedback == [
            {"rule": "Y", "line": 2, "message": "m2", "impact_tier": ""},
            {"rule": "X", "line": 5, "message": "m1", "fix": "fix1", "impact_tier": ""},
        ]

    def setup_method(self) -> None:
        from reporails_cli.interfaces.mcp import server

        server._validate_states.clear()

    teardown_method = setup_method

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_drops_a_workflow_finding_the_stored_project_workflow_never_counted(self) -> None:
        """`validate(path=<file>)` re-scopes discovery to one file, which can surface a
        whole-file content-expectation finding (`gate_mover`, empty `message`) the file never
        draws in real project context. The stored whole-project `validate`'s own workflow is
        ground truth — a `(rule, file)` pair absent from it is dropped, never served as
        `feedback` that pushes the remedy agent to add content the file never had."""
        from reporails_cli.interfaces.mcp import feedback, server

        server._validate_states[server._state_key("/proj", ())] = server._CircuitState(
            full_payload={
                "workflow": {
                    "locations": [
                        {
                            "order": 1,
                            "files": ["CLAUDE.md"],
                            "findings": [
                                {
                                    "rule": "CORE:C:0042",
                                    "file": "CLAUDE.md",
                                    "line": 3,
                                    "message": "Vague instruction.",
                                    "remedy": "Name it.",
                                    "impact_tier": "cosmetic",
                                }
                            ],
                        }
                    ]
                }
            }
        )
        single_file_payload = {
            "workflow": {
                "locations": [
                    {
                        "order": 1,
                        "files": ["CLAUDE.md"],
                        "findings": [
                            {
                                "rule": "CORE:C:0042",
                                "file": "CLAUDE.md",
                                "line": 3,
                                "message": "Vague instruction.",
                                "remedy": "Name it.",
                                "impact_tier": "cosmetic",
                            },
                            {
                                "rule": "CORE:C:0019",
                                "file": "CLAUDE.md",
                                "line": 0,
                                "message": "",
                                "remedy": "Add at least one explicit prohibition.",
                                "impact_tier": "gate_mover",
                            },
                        ],
                    }
                ]
            }
        }

        feedback = feedback.file_feedback(single_file_payload, Path("/proj/CLAUDE.md"), Path("/proj"))

        assert feedback == [
            {
                "rule": "CORE:C:0042",
                "line": 3,
                "message": "Vague instruction.",
                "impact_tier": "cosmetic",
            }
        ]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_drops_a_per_file_fallback_finding_the_stored_project_workflow_never_counted(self) -> None:
        """The same drop applies to the per-file fallback path (used when the current run's own
        workflow names no location for this file)."""
        from reporails_cli.interfaces.mcp import feedback, server

        server._validate_states[server._state_key("/proj", ())] = server._CircuitState(
            full_payload={
                "workflow": {
                    "locations": [
                        {
                            "order": 1,
                            "files": ["CLAUDE.md"],
                            "findings": [{"rule": "X", "file": "CLAUDE.md", "line": 5, "message": "m1"}],
                        }
                    ]
                }
            }
        )
        single_file_payload = {
            "files": {
                "CLAUDE.md": {
                    "count": 2,
                    "findings": [
                        {"rule": "X", "line": 5, "message": "m1", "fix": "fix1"},
                        {"rule": "CORE:S:0002", "line": 0, "message": "", "fix": "Add markdown section headings."},
                    ],
                }
            },
            "workflow": {"locations": [{"order": 1, "files": ["CLAUDE.md"], "findings": []}]},
        }

        feedback = feedback.file_feedback(single_file_payload, Path("/proj/CLAUDE.md"), Path("/proj"))

        assert feedback == [{"rule": "X", "line": 5, "message": "m1", "fix": "fix1", "impact_tier": ""}]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_no_stored_project_workflow_leaves_candidates_unfiltered(self) -> None:
        """When no whole-project `validate` is on record for the scan root (a targeted
        single-file `validate` with no earlier project-wide run), there is nothing to
        cross-check against — every candidate stays, matching pre-fix behavior."""
        from reporails_cli.interfaces.mcp import feedback

        payload = {
            "files": {
                "CLAUDE.md": {
                    "count": 1,
                    "findings": [{"rule": "CORE:S:0002", "line": 0, "message": "", "fix": "Add headings."}],
                }
            }
        }

        feedback = feedback.file_feedback(payload, Path("/proj/CLAUDE.md"), Path("/proj"))

        assert feedback == [
            {
                "rule": "CORE:S:0002",
                "line": 0,
                "message": "Section Headers Present",
                "fix": "Add headings.",
                "impact_tier": "",
            }
        ]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_empty_when_no_findings_either_way(self) -> None:
        from reporails_cli.interfaces.mcp import feedback

        payload = {"files": {"CLAUDE.md": {"count": 0, "findings": []}}}
        assert feedback.file_feedback(payload, Path("/proj/CLAUDE.md"), Path("/proj")) == []

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_capped_at_fifteen(self) -> None:
        from reporails_cli.interfaces.mcp import feedback

        findings = [{"rule": f"R{i}", "line": i, "message": "m", "fix": "f"} for i in range(20)]
        payload = {"files": {"CLAUDE.md": {"count": 20, "findings": findings}}}
        feedback = feedback.file_feedback(payload, Path("/proj/CLAUDE.md"), Path("/proj"))
        assert len(feedback) == 15
        assert [f["line"] for f in feedback] == list(range(15)), "weakest-first ties break on line, ascending"


class TestFeedbackWiring:
    """`validate(path=<file>)` on a file `remedy_brief` snapshotted carries a `feedback` block
    on both the bounded and full replies; an unsnapshotted file, or an error/needs_install
    payload, carries none."""

    def setup_method(self) -> None:
        from reporails_cli.interfaces.mcp import server, snapshots

        server._validate_states.clear()
        snapshots.clear_snapshots()

    teardown_method = setup_method

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    @requires_model
    @requires_rules
    def test_a_snapshotted_file_carries_feedback_on_both_bounded_and_full_replies(self, tmp_path: Path) -> None:
        from reporails_cli.interfaces.mcp import snapshots, tools

        target = tmp_path / "CLAUDE.md"
        target.write_text("# Project\n\nNever commit secrets.\n")

        bounded_before = _bounded_reply(target)
        assert "feedback" not in bounded_before, "not yet briefed"

        _payload, ruleset_map, score = tools.run_pipeline_for_path(str(target), True)
        snapshots.snapshot_file(target, ruleset_map, score, [])

        bounded_after = _bounded_reply(target)
        assert "feedback" in bounded_after
        assert isinstance(bounded_after["feedback"], list)

        full = json.loads(_call_tool("validate", {"path": str(target), "full": True}))
        assert "feedback" in full

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_an_error_or_needs_install_payload_carries_no_feedback(self, tmp_path: Path, monkeypatch) -> None:
        from reporails_cli.interfaces.mcp import server, snapshots

        target = tmp_path / "CLAUDE.md"
        target.write_text("# Project\n")
        monkeypatch.setattr(snapshots, "has_snapshot", lambda p: True)
        assert "feedback" not in server._with_feedback({"error": "x"}, target, tmp_path)
        assert "feedback" not in server._with_feedback({"needs_install": True}, target, tmp_path)


def _wf_finding(rule: str, line: int, tier: str = "cosmetic", message: str = "m") -> dict[str, Any]:
    return {"rule": rule, "file": "CLAUDE.md", "line": line, "message": message, "remedy": "r", "impact_tier": tier}


class TestFeedbackNewKinds:
    """A finding on the file whose rule was not firing on it in the stored whole-project reply
    reaches `validate(path=<file>)`'s `feedback`, through the real tool function."""

    def setup_method(self) -> None:
        from reporails_cli.interfaces.mcp import server, snapshots

        server._validate_states.clear()
        snapshots.clear_snapshots()

    teardown_method = setup_method

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_a_rule_newly_firing_after_an_edit_is_in_the_bounded_file_reply(self, tmp_path: Path, monkeypatch) -> None:
        from reporails_cli.interfaces.mcp import server, snapshots

        target = tmp_path / "CLAUDE.md"
        target.write_text("# Project\n\nNever commit secrets.\n")
        project_payload = {
            "files": {"CLAUDE.md": {"count": 2, "findings": []}},
            "workflow": {
                "locations": [
                    {"order": 1, "files": ["CLAUDE.md"], "findings": [_wf_finding("A", 3), _wf_finding("B", 5)]}
                ]
            },
        }
        file_payload = {
            "files": {
                "CLAUDE.md": {
                    "count": 3,
                    "findings": [
                        {"rule": "A", "line": 3, "message": "m", "fix": "r"},
                        {"rule": "B", "line": 5, "message": "m", "fix": "r"},
                        {
                            "rule": "CORE:G:0002",
                            "line": 7,
                            "message": "Credential in file.",
                            "fix": "Remove it.",
                            "severity": "error",
                        },
                    ],
                }
            },
            "workflow": {
                "locations": [
                    {"order": 1, "files": ["CLAUDE.md"], "findings": [_wf_finding("A", 3), _wf_finding("B", 5)]}
                ]
            },
        }
        replies = iter([(project_payload, None, 5.0), (file_payload, None, 5.0)])
        monkeypatch.setattr(server, "model_not_ready_error", lambda: None)
        monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: next(replies))
        monkeypatch.setattr(snapshots, "has_snapshot", lambda p: True)

        _call_tool("validate", {"path": str(tmp_path)})
        target.write_text('# Project\n\nNever commit secrets.\n\napi_key = "sk-live-0000000000000000"\n')
        reply = _bounded_reply(target)

        assert [f["rule"] for f in reply["feedback"]] == ["CORE:G:0002", "A", "B"]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_new_kinds_are_kept_ahead_of_repeats_errors_first_and_inside_the_cap(self) -> None:
        from reporails_cli.interfaces.mcp import feedback, server

        server._validate_states[server._state_key("/proj", ())] = server._CircuitState(
            full_payload={
                "workflow": {
                    "locations": [
                        {
                            "order": 1,
                            "files": ["CLAUDE.md"],
                            "findings": [_wf_finding(f"OLD{i}", i, "gate_mover") for i in range(20)],
                        }
                    ]
                }
            }
        )
        payload = {
            "files": {
                "CLAUDE.md": {
                    "count": 22,
                    "findings": [
                        {"rule": "NEWWARN", "line": 30, "message": "w", "fix": "f", "severity": "warning"},
                        {"rule": "NEWERR", "line": 31, "message": "e", "fix": "f", "severity": "error"},
                    ],
                }
            },
            "workflow": {
                "locations": [
                    {
                        "order": 1,
                        "files": ["CLAUDE.md"],
                        "findings": [_wf_finding(f"OLD{i}", i, "gate_mover") for i in range(20)],
                    }
                ]
            },
        }
        feedback = feedback.file_feedback(payload, Path("/proj/CLAUDE.md"), Path("/proj"))
        assert len(feedback) == 15
        assert [f["rule"] for f in feedback[:2]] == ["NEWERR", "NEWWARN"]
        assert [f["rule"] for f in feedback[2:5]] == ["OLD0", "OLD1", "OLD2"]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_no_stored_project_reply_keeps_an_error_finding(self) -> None:
        from reporails_cli.interfaces.mcp import feedback

        payload = {
            "files": {
                "CLAUDE.md": {
                    "count": 1,
                    "findings": [{"rule": "CORE:G:0002", "line": 7, "message": "c", "fix": "f", "severity": "error"}],
                }
            }
        }
        feedback = feedback.file_feedback(payload, Path("/proj/CLAUDE.md"), Path("/proj"))
        assert [f["rule"] for f in feedback] == ["CORE:G:0002"]


class TestFeedbackFiredBefore:
    """A rule that fired on the file anywhere in the stored whole-project reply (workflow or
    plain per-file findings) is not a new kind."""

    def setup_method(self) -> None:
        from reporails_cli.interfaces.mcp import server, snapshots

        server._validate_states.clear()
        snapshots.clear_snapshots()

    teardown_method = setup_method

    def _run(self, tmp_path: Path, monkeypatch, project_payload: dict, file_payload: dict) -> dict:
        from reporails_cli.interfaces.mcp import server, snapshots

        target = tmp_path / "CLAUDE.md"
        target.write_text("# Project\n\nNever commit secrets.\n")
        replies = iter([(project_payload, None, 5.0), (file_payload, None, 5.0)])
        monkeypatch.setattr(server, "model_not_ready_error", lambda: None)
        monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: next(replies))
        monkeypatch.setattr(snapshots, "has_snapshot", lambda p: True)
        _call_tool("validate", {"path": str(tmp_path)})
        target.write_text("# Project\n\nNever commit secrets.\n\nedited\n")
        return _bounded_reply(target)

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_a_rule_already_in_the_stored_per_file_findings_is_not_listed_as_new(self, tmp_path, monkeypatch) -> None:
        workflow = {"locations": [{"order": 1, "files": ["CLAUDE.md"], "findings": [_wf_finding("A", 3)]}]}
        project = {
            "files": {
                "CLAUDE.md": {
                    "count": 2,
                    "findings": [
                        {"rule": "A", "line": 3, "message": "m", "fix": "r"},
                        {"rule": "LOCAL", "line": 4, "message": "local", "fix": "f"},
                    ],
                }
            },
            "workflow": workflow,
        }
        after = {"files": project["files"], "workflow": workflow}
        reply = self._run(tmp_path, monkeypatch, project, after)
        assert [f["rule"] for f in reply["feedback"]] == ["A"]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_a_rule_that_fired_nowhere_before_is_listed_first_beside_a_per_file_only_rule(
        self, tmp_path, monkeypatch
    ) -> None:
        workflow = {"locations": [{"order": 1, "files": ["CLAUDE.md"], "findings": [_wf_finding("A", 3)]}]}
        project = {
            "files": {
                "CLAUDE.md": {"count": 2, "findings": [{"rule": "LOCAL", "line": 4, "message": "l", "fix": "f"}]}
            },
            "workflow": workflow,
        }
        after = {
            "files": {
                "CLAUDE.md": {
                    "count": 3,
                    "findings": [
                        {"rule": "LOCAL", "line": 4, "message": "l", "fix": "f"},
                        {"rule": "CORE:G:0002", "line": 7, "message": "c", "fix": "f", "severity": "error"},
                    ],
                }
            },
            "workflow": workflow,
        }
        reply = self._run(tmp_path, monkeypatch, project, after)
        assert [f["rule"] for f in reply["feedback"]] == ["CORE:G:0002", "A"]

    @pytest.mark.e2e
    @pytest.mark.subsys_server
    def test_a_stored_reply_without_a_workflow_lists_the_new_error_first_and_every_old_finding_once(
        self, tmp_path, monkeypatch
    ) -> None:
        project = {
            "files": {"CLAUDE.md": {"count": 1, "findings": [{"rule": "LOCAL", "line": 4, "message": "l", "fix": "f"}]}}
        }
        after = {
            "files": {
                "CLAUDE.md": {
                    "count": 2,
                    "findings": [
                        {"rule": "LOCAL", "line": 4, "message": "l", "fix": "f"},
                        {"rule": "CORE:G:0002", "line": 7, "message": "c", "fix": "f", "severity": "error"},
                    ],
                }
            }
        }
        reply = self._run(tmp_path, monkeypatch, project, after)
        assert [f["rule"] for f in reply["feedback"]] == ["CORE:G:0002", "LOCAL"]
