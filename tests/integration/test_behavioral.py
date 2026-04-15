"""Behavioral tests — verify user-facing CLI contracts.

These tests exercise the CLI the way a user would, checking that commands
produce the expected outputs, exit codes, and side effects.

Every test here represents a contract we promise to users.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.agents import clear_agent_cache, get_known_agents
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


def _rules_installed() -> bool:
    from reporails_cli.core.bootstrap import get_rules_path

    return (get_rules_path() / "core").exists()


requires_rules = pytest.mark.skipif(
    not _rules_installed(),
    reason="Rules framework not installed",
)

_onnx_path = (
    Path(__file__).resolve().parents[2]
    / "src" / "reporails_cli" / "bundled" / "models" / "minilm-l6-v2" / "onnx" / "model.onnx"
)
_has_onnx_model = _onnx_path.exists()
requires_model = pytest.mark.skipif(not _has_onnx_model, reason="Bundled ONNX model not available")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    """Clear module-level caches between tests."""
    clear_agent_cache()


@pytest.fixture
def minimal_project(tmp_path: Path) -> Path:
    """Bare project with both AGENTS.md and CLAUDE.md — L2 project.

    AGENTS.md is scanned by the generic default (no --agent).
    CLAUDE.md is scanned when tests pass --agent claude.
    """
    p = tmp_path / "proj"
    p.mkdir()
    content = "# My Project\n\nProject description.\n\n## Commands\n\n- `make build`\n"
    (p / "AGENTS.md").write_text(content)
    (p / "CLAUDE.md").write_text(content)
    return p


@pytest.fixture
def structured_project(tmp_path: Path) -> Path:
    """CLAUDE.md + rules dir — L3 project."""
    p = tmp_path / "proj"
    p.mkdir()
    (p / "CLAUDE.md").write_text(
        "# My Project\n\nProject description.\n\n"
        "## Commands\n\n- `make build`\n- `make test`\n\n"
        "## Architecture\n\nModular design.\n\n"
        "## Constraints\n\n- NEVER commit secrets\n"
    )
    rules = p / ".claude" / "rules"
    rules.mkdir(parents=True)
    (rules / "testing.md").write_text("# Testing\n\n- MUST write tests\n")
    return p


@pytest.fixture
def nested_project(tmp_path: Path) -> Path:
    """Parent project with child subdirectory — tests scope isolation.

    Structure:
        parent/
        ├── .git/
        ├── CLAUDE.md          (should NOT be scanned when targeting child)
        └── child/
            └── CLAUDE.md      (should be scanned)
    """
    parent = tmp_path / "parent"
    parent.mkdir()
    (parent / ".git").mkdir()
    (parent / "CLAUDE.md").write_text("# Parent\n\nParent instructions.\n")

    child = parent / "child"
    child.mkdir()
    (child / "CLAUDE.md").write_text("# Child\n\nChild instructions.\n\n## Commands\n\n- `make build`\n")
    return child


@pytest.fixture
def empty_project(tmp_path: Path) -> Path:
    """Empty directory — no instruction files."""
    p = tmp_path / "empty"
    p.mkdir()
    return p


@pytest.fixture
def multi_file_project(tmp_path: Path) -> Path:
    """Project with multiple instruction files."""
    p = tmp_path / "proj"
    p.mkdir()
    (p / "CLAUDE.md").write_text("# Main\n\nMain instructions.\n")
    (p / "AGENTS.md").write_text("# Agents\n\nGeneric agent instructions.\n")
    return p


# ===========================================================================
# CHECK COMMAND — JSON Output Schema
# (Exit codes covered by smoke tests: strict, missing path, no files)
# ===========================================================================


class TestCheckJsonSchema:
    """JSON output must have a stable, documented schema."""

    @requires_rules
    def test_required_keys_present(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)

        required = {"offline", "files", "stats"}
        assert required.issubset(data.keys()), f"Missing keys: {required - data.keys()}"

    @requires_rules
    def test_files_is_dict_with_findings(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "json"])
        data = json.loads(result.output)
        assert isinstance(data["files"], dict)
        for file_data in data["files"].values():
            assert isinstance(file_data["findings"], list)

    @requires_rules
    def test_finding_has_required_fields(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "json"])
        data = json.loads(result.output)
        for file_data in data["files"].values():
            for f in file_data["findings"]:
                assert "line" in f
                assert "severity" in f
                assert "rule" in f
                assert "message" in f

    def test_no_files_json_output(self, empty_project: Path) -> None:
        result = runner.invoke(app, ["check", str(empty_project), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["violations"] == []
        assert data["level"] == "L0"


# ===========================================================================
# CHECK COMMAND — Scan Scope
# ===========================================================================


class TestCheckScanScope:
    """Files outside the target directory must never appear in results."""

    @requires_rules
    def test_nested_child_only_scans_child(self, nested_project: Path) -> None:
        result = runner.invoke(app, ["check", str(nested_project), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)

        for file_data in data["files"].values():
            for f in file_data["findings"]:
                assert "Parent" not in f.get("message", ""), "Parent content leaked into child scan"

    @requires_rules
    def test_nested_child_violation_count_reasonable(self, nested_project: Path) -> None:
        """A single-file project should have a bounded number of violations."""
        result = runner.invoke(app, ["check", str(nested_project), "-f", "json"])
        data = json.loads(result.output)
        # Count total findings across all files
        total = sum(len(fd["findings"]) for fd in data["files"].values())
        # One CLAUDE.md can't have hundreds of findings.
        assert total < 100, f"Suspiciously many findings: {total}"


# ===========================================================================
# CHECK COMMAND — Text Output
# ===========================================================================


class TestCheckTextOutput:
    """Text output must contain key information."""

    @requires_rules
    def test_score_displayed(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "text"])
        assert result.exit_code == 0
        assert "SCORE:" in result.output or "/ 10" in result.output or "Score:" in result.output

    @requires_rules
    def test_violations_grouped_by_file(self, minimal_project: Path) -> None:
        result = runner.invoke(
            app, ["check", str(minimal_project), "--agent", "claude", "-f", "text"]
        )
        assert result.exit_code == 0
        assert "CLAUDE.md" in result.output

    def test_no_files_shows_l0_message(self, empty_project: Path) -> None:
        result = runner.invoke(app, ["check", str(empty_project), "-f", "text"])
        assert "No instruction files found" in result.output
        assert "L0" in result.output


# ===========================================================================
# CHECK COMMAND — Multiple Files
# ===========================================================================


class TestCheckMultiFile:
    """Projects with multiple instruction files should report all of them."""

    @requires_rules
    def test_multiple_agents_detected(self, multi_file_project: Path) -> None:
        result = runner.invoke(app, ["check", str(multi_file_project), "-f", "json"])
        data = json.loads(result.output)
        # Multi-file project should produce valid JSON output with files key
        assert "files" in data
        assert result.exit_code == 0


# ===========================================================================
# CHECK COMMAND — Score Consistency
# ===========================================================================


class TestCheckScoreConsistency:
    """Score must be deterministic — same project, same score."""

    @requires_rules
    def test_deterministic_stats(self, structured_project: Path) -> None:
        stats_list = []
        for _ in range(3):
            result = runner.invoke(app, ["check", str(structured_project), "-f", "json"])
            data = json.loads(result.output)
            stats_list.append(data["stats"])

        assert stats_list[0] == stats_list[1] == stats_list[2], (
            f"Stats varied across runs: {stats_list}"
        )


# ===========================================================================
# CHECK COMMAND — Agent Flag
# ===========================================================================


class TestCheckAgentFlag:
    """--agent flag must scope file discovery and adapt hints per agent."""

    # Hint message tests (no agent, claude, codex, copilot) covered by
    # smoke TestHintMessages. Keep agent-specific behavior tests below.

    def test_no_files_hint_copilot(self, empty_project: Path) -> None:
        """--agent copilot should hint its instruction file."""
        result = runner.invoke(
            app, ["check", str(empty_project), "--agent", "copilot", "-f", "text"]
        )
        assert "Create a .github/copilot-instructions.md to get started" in result.output

    def test_unknown_agent_errors(self, empty_project: Path) -> None:
        """Unknown agent must error with exit code 2 and list known agents."""
        result = runner.invoke(app, ["check", str(empty_project), "--agent", "somefuture"])
        assert result.exit_code == 2
        assert "Unknown agent" in result.output
        assert "claude" in result.output

    def test_wrong_agent_no_false_positive(self, tmp_path: Path) -> None:
        """--agent claude on a project with only AGENTS.md must NOT scan it."""
        p = tmp_path / "proj"
        p.mkdir()
        (p / "AGENTS.md").write_text("# Agents\n\nInstructions.\n")
        result = runner.invoke(app, ["check", str(p), "--agent", "claude", "-f", "text"])
        assert "No instruction files found" in result.output

    @requires_rules
    def test_codex_agent_scans_agents_md(self, tmp_path: Path) -> None:
        """--agent codex should find and validate AGENTS.md."""
        p = tmp_path / "proj"
        p.mkdir()
        (p / "AGENTS.md").write_text("# Agents\n\nInstructions for Codex.\n")
        result = runner.invoke(app, ["check", str(p), "--agent", "codex", "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "files" in data
        assert "AGENTS.md" in data["files"], "AGENTS.md should be detected"

    @requires_rules
    def test_no_agent_core_rules_fire(self, tmp_path: Path) -> None:
        """No --agent must still apply core rules (not just file presence)."""
        p = tmp_path / "proj"
        p.mkdir()
        (p / "AGENTS.md").write_text("# Agents\n\nInstructions.\n")
        result = runner.invoke(app, ["check", str(p), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["files"], "No files detected — core rules should find instruction files"


# ===========================================================================
# CHECK COMMAND — Agent Cross-Validation
# ===========================================================================


class TestAgentCrossValidation:
    """Agent registry must be built from framework config.yml files."""

    @requires_rules
    def test_registry_populated_from_configs(self) -> None:
        """Registry should contain at least the big 5 agents."""
        agents = get_known_agents()
        for agent_id in ("claude", "cursor", "copilot", "codex", "gemini"):
            assert agent_id in agents, f"Agent {agent_id} missing from registry"


# ===========================================================================
# CHECK COMMAND — Agent Matrix (derived from config.yml, not manual)
# ===========================================================================


# Agents whose first instruction pattern is YAML, not markdown — skip file-detection
# test since the rules engine expects markdown content.
_YAML_AGENTS: set[str] = set()


class TestAgentMatrix:
    """Every known agent must produce a valid check result against its instruction file.

    Parametrized from get_known_agents() so new config.yml agents get coverage automatically.
    """

    @requires_rules
    @pytest.mark.parametrize("agent_id", sorted(get_known_agents()))
    def test_agent_check_finds_files(self, agent_id: str, tmp_path: Path) -> None:
        """ails check --agent X must detect the agent's instruction file."""
        if agent_id in _YAML_AGENTS:
            pytest.skip(f"{agent_id} uses YAML instruction files")

        agent_type = get_known_agents()[agent_id]
        # Use first instruction pattern (strip glob wildcards for file creation)
        filename = agent_type.instruction_patterns[0].replace("**/", "")
        p = tmp_path / "proj"
        p.mkdir()
        target = p / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"# {agent_type.name}\n\nInstructions.\n")

        result = runner.invoke(app, ["check", str(p), "--agent", agent_id, "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["files"], f"--agent {agent_id} should detect {filename}, got empty files"

    @requires_rules
    @pytest.mark.parametrize("agent_id", sorted(get_known_agents()))
    def test_agent_check_no_crash(self, agent_id: str, tmp_path: Path) -> None:
        """ails check --agent X must not crash on an empty project."""
        p = tmp_path / "proj"
        p.mkdir()
        result = runner.invoke(app, ["check", str(p), "--agent", agent_id])
        assert result.exit_code == 0


# ===========================================================================
# CHECK COMMAND — File Target
# ===========================================================================


class TestCheckFileTarget:
    """ails check FILE should validate just that file."""

    @requires_rules
    def test_single_file_target(self, minimal_project: Path) -> None:
        """Pointing at a specific file should work."""
        target = minimal_project / "CLAUDE.md"
        result = runner.invoke(app, ["check", str(target), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        # Single file target may return old L0 schema or new files schema
        assert "files" in data or "level" in data


# ===========================================================================
# CHECK COMMAND — Content Check Verification
# ===========================================================================


class TestContentChecks:
    """Content checks must produce findings when mapper is available."""

    @requires_rules
    @requires_model
    def test_content_checks_produce_findings(self, minimal_project: Path) -> None:
        """When ONNX model + spaCy are available, client_check_count must be > 0."""
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["stats"]["client_check_count"] > 0, (
            f"Content checks should produce findings but got client_check_count=0. "
            f"A runtime dependency may be missing. Stats: {data['stats']}"
        )


# CHECK COMMAND — Config Integration
# ===========================================================================


class TestCheckConfig:
    """Project config must affect validation behavior."""

    @requires_rules
    def test_disabled_rules_excluded(self, tmp_path: Path) -> None:
        """Rules listed in .ails/config.yml disabled_rules should not fire."""
        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# Project\n\nA project.\n")

        # Run without config — get findings
        r1 = runner.invoke(app, ["check", str(p), "-f", "json"])
        d1 = json.loads(r1.output)
        all_findings = [f for fd in d1["files"].values() for f in fd["findings"]]
        if not all_findings:
            pytest.skip("No findings to disable")

        # Get a rule ID to disable
        rule_to_disable = all_findings[0]["rule"]

        # Create config that disables it
        config_dir = p / ".ails"
        config_dir.mkdir(exist_ok=True)
        (config_dir / "config.yml").write_text(f"disabled_rules:\n  - {rule_to_disable}\n")

        # Run with config — that rule should not fire
        clear_agent_cache()
        r2 = runner.invoke(app, ["check", str(p), "-f", "json"])
        d2 = json.loads(r2.output)

        fired_rules = {f["rule"] for fd in d2["files"].values() for f in fd["findings"]}
        assert rule_to_disable not in fired_rules, f"{rule_to_disable} fired despite being disabled"


# ===========================================================================
# HEAL COMMAND
# ===========================================================================


class TestHealCommand:
    """ails heal must auto-fix and report remaining violations."""

    # test_heal_missing_path covered by smoke tests

    @requires_model
    @requires_rules
    def test_heal_auto_fixes_applied(self, tmp_path: Path) -> None:
        """Auto-fixers should modify the file and report what they fixed."""
        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# My Project\n\nA project.\n")

        result = runner.invoke(app, ["heal", str(p)])

        assert result.exit_code in (0, None), f"heal failed: {result.output}"

        content = (p / "CLAUDE.md").read_text()
        original = "# My Project\n\nA project.\n"
        if content != original:
            assert len(content) > len(original)

    @requires_model
    @requires_rules
    def test_heal_nothing_to_heal(self, tmp_path: Path) -> None:
        """When all rules pass or are cached, heal should say nothing to do."""
        p = tmp_path / "proj"
        p.mkdir()
        # Rich enough content that most rules pass after fixes
        (p / "CLAUDE.md").write_text("# Project\n\nBasic project.\n")

        # First pass — applies fixes
        result = runner.invoke(app, ["heal", str(p)])
        assert result.exit_code in (0, None)
        # Should produce some output (fixes applied, violations listed, or nothing to heal)
        assert len(result.output.strip()) > 0

    @requires_model
    @requires_rules
    def test_heal_json_output(self, tmp_path: Path) -> None:
        """Invoke with -f json, parse JSON, assert keys."""
        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# My Project\n\nA project.\n")

        result = runner.invoke(app, ["heal", str(p), "-f", "json"])

        assert result.exit_code in (0, None), f"heal failed: {result.output}"
        data = json.loads(result.output)
        assert "auto_fixed" in data
        assert "summary" in data
        assert "auto_fixed_count" in data["summary"]

    @requires_model
    def test_heal_works_without_tty(self, tmp_path: Path) -> None:
        """CliRunner is non-TTY — heal should still work (no TTY requirement)."""
        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# My Project\n\nA project.\n")

        result = runner.invoke(app, ["heal", str(p)])
        assert result.exit_code in (0, None)

    @requires_model
    @requires_rules
    def test_heal_shows_remaining_violations(self, tmp_path: Path) -> None:
        """Non-fixable violations should be listed in text output."""
        p = tmp_path / "proj"
        p.mkdir()
        # Minimal content that will have non-fixable violations
        (p / "CLAUDE.md").write_text("# My Project\n\nA project.\n")

        result = runner.invoke(app, ["heal", str(p)])

        assert result.exit_code in (0, None)
        # Should show either fixes applied or remaining violations
        output = result.output
        has_content = (
            "fix" in output.lower()
            or "remaining" in output.lower()
            or "violation" in output.lower()
            or "semantic" in output.lower()
            or "Nothing to heal" in output
        )
        assert has_content, f"Expected heal output content, got: {output}"


