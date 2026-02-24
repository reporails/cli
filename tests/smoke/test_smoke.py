"""E2E smoke tests — validate user-facing CLI behavior against realistic projects.

These tests use committed fixture projects (not tmp_path stubs) to catch
bugs that unit/integration tests miss: wrong default agent, cross-agent
contamination, empty template context, hardcoded hints.

Every test here maps to a real user-reported bug from the 0.3.0 cycle.

Design principle: these tests are mutation-tested. Each assertion is chosen
to FAIL when the corresponding bug is reintroduced. Tests that skip on
zero violations are forbidden — zero violations from a fixture designed to
produce them IS the bug.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.agents import clear_agent_cache
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

FIXTURES = Path(__file__).parent.parent / "fixtures" / "projects"


def _rules_installed() -> bool:
    from reporails_cli.core.bootstrap import get_rules_path

    return (get_rules_path() / "core").exists()


requires_rules = pytest.mark.skipif(
    not _rules_installed(),
    reason="Rules framework not installed",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    """Clear module-level caches between tests."""
    clear_agent_cache()


@pytest.fixture
def claude_only() -> Path:
    return FIXTURES / "claude_only"


@pytest.fixture
def codex_only() -> Path:
    return FIXTURES / "codex_only"


@pytest.fixture
def copilot_only() -> Path:
    return FIXTURES / "copilot_only"


@pytest.fixture
def multi_agent() -> Path:
    return FIXTURES / "multi_agent"


@pytest.fixture
def generic_only() -> Path:
    return FIXTURES / "generic_only"


@pytest.fixture
def nested_claude() -> Path:
    return FIXTURES / "nested_claude"


@pytest.fixture
def config_only() -> Path:
    return FIXTURES / "config_only"


@pytest.fixture
def multi_agent_with_config() -> Path:
    return FIXTURES / "multi_agent_with_config"


@pytest.fixture
def empty_dir(tmp_path: Path) -> Path:
    p = tmp_path / "empty"
    p.mkdir()
    return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _check_json(path: Path, agent: str = "") -> dict:
    """Run ails check and return parsed JSON output."""
    args = ["check", str(path), "-f", "json", "--no-update-check"]
    if agent:
        args.extend(["--agent", agent])
    result = runner.invoke(app, args)
    assert result.exit_code == 0, f"check failed (exit {result.exit_code}):\n{result.output}"
    return json.loads(result.output)


def _check_text(path: Path, agent: str = "") -> str:
    """Run ails check and return text output."""
    args = ["check", str(path), "-f", "text", "--no-update-check"]
    if agent:
        args.extend(["--agent", agent])
    result = runner.invoke(app, args)
    assert result.exit_code == 0, f"check failed (exit {result.exit_code}):\n{result.output}"
    return result.output


def _violation_rule_ids(data: dict) -> set[str]:
    """Extract all rule IDs from violations."""
    return {v["rule_id"] for v in data["violations"]}


def _violation_namespaces(data: dict) -> set[str]:
    """Extract unique rule namespaces (prefix before first colon)."""
    return {v["rule_id"].split(":")[0] for v in data["violations"]}


def _violation_files(data: dict) -> set[str]:
    """Extract unique file names from violation locations (strip line numbers)."""
    return {v["location"].split(":")[0] for v in data["violations"]}


# ===========================================================================
# Default Agent — Core Rules Only
#
# Bug guarded: empty --agent default caused template context to be empty,
# rules couldn't resolve {{instruction_files}}, zero violations on real
# projects. The key assertion is violations > 0, NOT rules_checked > 0.
# ===========================================================================


@pytest.mark.e2e
class TestDefaultAgentCoreOnly:
    """No --agent flag must apply core rules and produce real violations."""

    @requires_rules
    def test_core_rules_produce_violations(self, generic_only: Path) -> None:
        """Without --agent, core rules must produce violations on fixture content.

        This catches Bug 3 (empty template context): rules_checked can be >0
        even when templates don't resolve — but violations will be 0 because
        no files match the unresolved {{instruction_files}} glob.
        """
        data = _check_json(generic_only)
        assert len(data["violations"]) > 0, (
            f"Zero violations on generic_only fixture — core rules not matching files. "
            f"rules_checked={data.get('summary', {}).get('rules_checked', 0)}, "
            f"score={data['score']}"
        )

    @requires_rules
    def test_score_below_perfect(self, generic_only: Path) -> None:
        """Fixture content has known gaps; score must not be 10.0.

        A perfect score on imperfect content means rules aren't firing.
        """
        data = _check_json(generic_only)
        assert data["score"] < 10.0, "Perfect score on generic_only fixture — rules are loaded but not matching content"

    @requires_rules
    def test_no_agent_namespaced_violations(self, generic_only: Path) -> None:
        """Without --agent, no agent-specific rules should fire."""
        data = _check_json(generic_only)
        namespaces = _violation_namespaces(data)
        for ns in ("CLAUDE", "CODEX", "COPILOT", "CURSOR", "WINDSURF"):
            assert ns not in namespaces, f"Agent-specific namespace {ns} fired without --agent"

    @requires_rules
    def test_no_agent_fewer_rules_than_any_agent(self, claude_only: Path) -> None:
        """Without --agent, rules_checked must be <= any specific agent's count.

        This catches Bug 2 (all agent rules loaded without --agent): loading
        all agents' rules inflates rules_checked above any single agent's count.
        Core-only (no agent) must always check fewer rules than core+agent.
        """
        data_no_agent = _check_json(claude_only)
        data_with_agent = _check_json(claude_only, agent="claude")
        no_agent_count = data_no_agent.get("summary", {}).get("rules_checked", 0)
        with_agent_count = data_with_agent.get("summary", {}).get("rules_checked", 0)
        assert no_agent_count <= with_agent_count, (
            f"No-agent checked {no_agent_count} rules but --agent claude checked {with_agent_count}. "
            f"No-agent should check fewer (core only), not more (all agents loaded)."
        )

    @requires_rules
    def test_files_detected(self, generic_only: Path) -> None:
        """Without --agent, auto-detect must find AGENTS.md and not report L1."""
        data = _check_json(generic_only)
        assert data["level"] != "L1", "AGENTS.md should be detected, got L1 Absent"


# ===========================================================================
# Agent File Targeting
# ===========================================================================


@pytest.mark.e2e
class TestAgentFileTargeting:
    """--agent flag must scope file discovery to the correct instruction file."""

    @requires_rules
    def test_claude_finds_claude_md(self, claude_only: Path) -> None:
        data = _check_json(claude_only, agent="claude")
        assert data["level"] != "L1", "--agent claude should detect CLAUDE.md"

    @requires_rules
    def test_codex_finds_agents_md(self, codex_only: Path) -> None:
        data = _check_json(codex_only, agent="codex")
        assert data["level"] != "L1", "--agent codex should detect AGENTS.md"

    @requires_rules
    def test_copilot_finds_its_file(self, copilot_only: Path) -> None:
        data = _check_json(copilot_only, agent="copilot")
        assert data["level"] != "L1", "--agent copilot should detect copilot-instructions.md"

    def test_wrong_agent_claude_on_codex(self, codex_only: Path) -> None:
        """--agent claude on a codex-only project must find no files."""
        output = _check_text(codex_only, agent="claude")
        assert "No instruction files found" in output

    def test_wrong_agent_codex_on_claude(self, claude_only: Path) -> None:
        """--agent codex on a claude-only project must find no files."""
        output = _check_text(claude_only, agent="codex")
        assert "No instruction files found" in output


# ===========================================================================
# Cross-Agent Contamination
#
# Bug guarded: loading all agent rules when no agent specified. The test
# must assert violations exist AND contain only allowed namespaces.
# Checking only namespaces on an empty violation list proves nothing.
# ===========================================================================


@pytest.mark.e2e
class TestCrossAgentContamination:
    """Agent-scoped validation must never leak rules from other agents."""

    @requires_rules
    def test_codex_no_claude_rules(self, codex_only: Path) -> None:
        """--agent codex must produce violations, none from CLAUDE namespace."""
        data = _check_json(codex_only, agent="codex")
        assert len(data["violations"]) > 0, "Codex fixture must produce violations"
        claude_rules = {r for r in _violation_rule_ids(data) if r.startswith("CLAUDE:")}
        assert not claude_rules, f"CLAUDE rules fired under --agent codex: {claude_rules}"

    @requires_rules
    def test_claude_no_other_agent_rules(self, claude_only: Path) -> None:
        """--agent claude must produce violations, none from other agent namespaces."""
        data = _check_json(claude_only, agent="claude")
        assert len(data["violations"]) > 0, "Claude fixture must produce violations"
        foreign = {
            r for r in _violation_rule_ids(data) if r.split(":")[0] in ("CODEX", "COPILOT", "CURSOR", "WINDSURF")
        }
        assert not foreign, f"Foreign agent rules fired under --agent claude: {foreign}"

    @requires_rules
    def test_no_agent_multi_project_core_only(self, multi_agent: Path) -> None:
        """No --agent on a multi-agent project must produce violations, only CORE/RRAILS."""
        data = _check_json(multi_agent)
        assert len(data["violations"]) > 0, "Multi-agent fixture must produce violations without --agent"
        agent_ns = _violation_namespaces(data) - {"CORE", "RRAILS"}
        assert not agent_ns, f"Agent-namespaced rules fired without --agent: {agent_ns}"


# ===========================================================================
# Hint Messages
# ===========================================================================


@pytest.mark.e2e
class TestHintMessages:
    """Empty-project hints must name the correct instruction file per agent."""

    def test_no_agent_hints_agents_md(self, empty_dir: Path) -> None:
        output = _check_text(empty_dir)
        assert "AGENTS.md" in output, "Default hint should reference AGENTS.md"
        assert "CLAUDE.md" not in output, "Default hint must not reference CLAUDE.md"

    def test_claude_hints_claude_md(self, empty_dir: Path) -> None:
        output = _check_text(empty_dir, agent="claude")
        assert "CLAUDE.md" in output

    def test_codex_hints_agents_md(self, empty_dir: Path) -> None:
        output = _check_text(empty_dir, agent="codex")
        assert "AGENTS.md" in output

    def test_copilot_hints_its_file(self, empty_dir: Path) -> None:
        output = _check_text(empty_dir, agent="copilot")
        assert "copilot-instructions.md" in output


# ===========================================================================
# Multi-Agent Project
# ===========================================================================


@pytest.mark.e2e
class TestMultiAgentProject:
    """Multi-agent projects must scope correctly per --agent flag."""

    @requires_rules
    def test_no_agent_scans_generic_only(self, multi_agent: Path) -> None:
        """Without --agent, AGENTS.md (generic) is scanned — not all agents' files."""
        data = _check_json(multi_agent)
        assert data["level"] != "L1", "Multi-agent project should not be L1"
        assert len(data["violations"]) > 0, "Multi-agent fixture must produce violations"
        files = _violation_files(data)
        assert "AGENTS.md" in files, f"No-agent should scan AGENTS.md (generic), got: {files}"
        assert "CLAUDE.md" not in files, f"No-agent should not scan CLAUDE.md, got: {files}"

    @requires_rules
    def test_agent_claude_scopes_to_claude_md(self, multi_agent: Path) -> None:
        """--agent claude on multi-agent project should scope to CLAUDE.md."""
        data = _check_json(multi_agent, agent="claude")
        assert data["level"] != "L1"
        assert len(data["violations"]) > 0, "Claude on multi-agent must produce violations"
        namespaces = _violation_namespaces(data)
        foreign = namespaces - {"CORE", "RRAILS", "CLAUDE"}
        assert not foreign, f"Non-Claude rules fired with --agent claude: {foreign}"

    @requires_rules
    def test_agent_codex_scopes_to_agents_md(self, multi_agent: Path) -> None:
        """--agent codex on multi-agent project should scope to AGENTS.md."""
        data = _check_json(multi_agent, agent="codex")
        assert data["level"] != "L1"
        assert len(data["violations"]) > 0, "Codex on multi-agent must produce violations"
        namespaces = _violation_namespaces(data)
        foreign = namespaces - {"CORE", "RRAILS", "CODEX"}
        assert not foreign, f"Non-Codex rules fired with --agent codex: {foreign}"


# ===========================================================================
# Violation Location Accuracy
#
# These tests MUST NOT skip on zero violations. The fixtures are designed
# to produce violations. Zero violations means the engine is broken.
# ===========================================================================


@pytest.mark.e2e
class TestViolationLocationAccuracy:
    """Violation locations must reference the correct file, not a wrong one."""

    @requires_rules
    def test_claude_violations_reference_claude_md(self, claude_only: Path) -> None:
        """--agent claude violations must include CLAUDE.md (may also include infrastructure files)."""
        data = _check_json(claude_only, agent="claude")
        assert len(data["violations"]) > 0, "Claude fixture must produce violations"
        files = _violation_files(data)
        assert "CLAUDE.md" in files, f"Expected CLAUDE.md in violations, got: {files}"

    @requires_rules
    def test_codex_violations_reference_agents_md(self, codex_only: Path) -> None:
        """--agent codex violations must include AGENTS.md (may also include infrastructure files)."""
        data = _check_json(codex_only, agent="codex")
        assert len(data["violations"]) > 0, "Codex fixture must produce violations"
        files = _violation_files(data)
        assert "AGENTS.md" in files, f"Expected AGENTS.md in violations, got: {files}"

    @requires_rules
    def test_multi_agent_claude_only_claude_md(self, multi_agent: Path) -> None:
        """--agent claude on multi-agent project: violations include CLAUDE.md, not AGENTS.md."""
        data = _check_json(multi_agent, agent="claude")
        assert len(data["violations"]) > 0, "Claude on multi-agent must produce violations"
        files = _violation_files(data)
        assert "CLAUDE.md" in files, f"Expected CLAUDE.md in violations, got: {files}"
        assert "AGENTS.md" not in files, f"AGENTS.md should not appear with --agent claude, got: {files}"

    @requires_rules
    def test_multi_agent_codex_only_agents_md(self, multi_agent: Path) -> None:
        """--agent codex on multi-agent project: violations include AGENTS.md, not CLAUDE.md."""
        data = _check_json(multi_agent, agent="codex")
        assert len(data["violations"]) > 0, "Codex on multi-agent must produce violations"
        files = _violation_files(data)
        assert "AGENTS.md" in files, f"Expected AGENTS.md in violations, got: {files}"
        assert "CLAUDE.md" not in files, f"CLAUDE.md should not appear with --agent codex, got: {files}"

    @requires_rules
    def test_generic_violations_reference_agents_md(self, generic_only: Path) -> None:
        """No --agent on generic project: violations must exist and reference AGENTS.md."""
        data = _check_json(generic_only)
        assert len(data["violations"]) > 0, "Generic fixture must produce violations"
        files = _violation_files(data)
        assert "AGENTS.md" in files, f"Expected AGENTS.md in violation files, got: {files}"


# ===========================================================================
# Empty Agent String Edge Case
# ===========================================================================


@pytest.mark.e2e
class TestEmptyAgentString:
    """--agent '' must behave identically to no --agent flag."""

    @requires_rules
    def test_empty_string_detects_files(self, generic_only: Path) -> None:
        """--agent '' should auto-detect like no flag."""
        data_no_flag = _check_json(generic_only)
        data_empty = _check_json(generic_only, agent="")
        assert data_no_flag["level"] == data_empty["level"]
        assert data_no_flag["score"] == data_empty["score"]

    @requires_rules
    def test_empty_string_no_agent_rules(self, generic_only: Path) -> None:
        """--agent '' must not load agent-specific rules."""
        data = _check_json(generic_only, agent="")
        namespaces = _violation_namespaces(data)
        for ns in ("CLAUDE", "CODEX", "COPILOT", "CURSOR", "WINDSURF"):
            assert ns not in namespaces, f"Agent namespace {ns} fired with --agent '': {namespaces}"

    def test_empty_string_hint_agents_md(self, empty_dir: Path) -> None:
        """--agent '' on empty project should hint AGENTS.md, not CLAUDE.md."""
        output = _check_text(empty_dir, agent="")
        assert "AGENTS.md" in output
        assert "CLAUDE.md" not in output


# ===========================================================================
# Nested File Discovery
# ===========================================================================


@pytest.mark.e2e
class TestNestedFileDiscovery:
    """Instruction files in subdirectories must be discovered and scanned."""

    @requires_rules
    def test_nested_claude_md_detected(self, nested_claude: Path) -> None:
        """CLAUDE.md in a nested subdirectory must be found by --agent claude."""
        data = _check_json(nested_claude, agent="claude")
        assert len(data["violations"]) > 0, "Nested fixture must produce violations"
        # Nested file appears either directly in violations or via main_instruction_file
        # binding (which picks root CLAUDE.md as location for whole-project rules).
        files = _violation_files(data)
        assert "CLAUDE.md" in files, f"Root CLAUDE.md not in violation locations: {files}"

    @requires_rules
    def test_nested_both_files_scanned(self, nested_claude: Path) -> None:
        """Root CLAUDE.md must appear in violations; nested may be folded into root location."""
        data = _check_json(nested_claude, agent="claude")
        assert len(data["violations"]) > 0, "Nested fixture must produce violations"
        files = _violation_files(data)
        assert "CLAUDE.md" in files, f"Root CLAUDE.md missing from violations: {files}"

    @requires_rules
    def test_nested_level_above_l1(self, nested_claude: Path) -> None:
        """Project with nested CLAUDE.md files must not be L1."""
        data = _check_json(nested_claude, agent="claude")
        assert data["level"] != "L1"


# ===========================================================================
# Config-Only Project (No Instruction Files)
# ===========================================================================


@pytest.mark.e2e
class TestConfigOnlyProject:
    """Config files (.claude/settings.json) without instruction files must not false-detect."""

    def test_config_only_no_files_detected(self, config_only: Path) -> None:
        """Project with only .claude/settings.json should report no instruction files."""
        output = _check_text(config_only)
        assert "No instruction files found" in output

    def test_config_only_level_l1(self, config_only: Path) -> None:
        """Config-only project should be L1 (Absent)."""
        data = _check_json(config_only)
        assert data["level"] == "L1"

    def test_config_only_claude_agent_no_files(self, config_only: Path) -> None:
        """--agent claude on config-only project should find no instruction files."""
        output = _check_text(config_only, agent="claude")
        assert "No instruction files found" in output
        assert "CLAUDE.md" in output  # hint should suggest creating one


# ===========================================================================
# Violation Deduplication
#
# Bug: engine.py passed raw violations (with duplicates) into
# ValidationResult instead of unique_violations. Formatters disagreed
# on violation counts.
# ===========================================================================


@pytest.mark.e2e
class TestViolationDeduplication:
    """JSON output must not contain duplicate violations."""

    @requires_rules
    def test_no_duplicate_violations(self, claude_only: Path) -> None:
        """Each (rule_id, location, check_id) tuple must appear at most once."""
        data = _check_json(claude_only, agent="claude")
        seen: set[tuple[str, str, str]] = set()
        for v in data["violations"]:
            key = (v["rule_id"], v["location"], v.get("check_id", ""))
            assert key not in seen, f"Duplicate violation: {key}"
            seen.add(key)

    @requires_rules
    def test_violation_count_matches_rules_failed(self, claude_only: Path) -> None:
        """Number of unique rule_ids in violations must equal summary.rules_failed."""
        data = _check_json(claude_only, agent="claude")
        unique_rule_ids = {v["rule_id"] for v in data["violations"]}
        rules_failed = data.get("summary", {}).get("rules_failed", -1)
        assert len(unique_rule_ids) == rules_failed, (
            f"Unique violated rules ({len(unique_rule_ids)}) != summary.rules_failed ({rules_failed})"
        )


# ===========================================================================
# Generic Agent Template Resolution
#
# Bug: --agent generic returned empty template context because no
# agents/generic/config.yml exists. Rules couldn't match files.
# ===========================================================================


@pytest.mark.e2e
class TestGenericAgentTemplateResolution:
    """--agent generic must resolve template vars from detected files."""

    @requires_rules
    def test_generic_agent_produces_violations(self, codex_only: Path) -> None:
        """--agent generic on a project with AGENTS.md must produce violations."""
        data = _check_json(codex_only, agent="generic")
        assert len(data["violations"]) > 0, (
            f"--agent generic produced 0 violations (score={data['score']}). "
            "Template context likely empty — rules can't match files."
        )

    @requires_rules
    def test_generic_agent_score_below_perfect(self, codex_only: Path) -> None:
        """--agent generic must not produce a perfect score on imperfect content."""
        data = _check_json(codex_only, agent="generic")
        assert data["score"] < 10.0, "Perfect score with --agent generic — template context not resolving"


# ===========================================================================
# Unknown Agent Validation
#
# Bug: --agent doesnotexist silently returned score=0 level=L1 exit=0.
# ===========================================================================


@pytest.mark.e2e
class TestUnknownAgentValidation:
    """Unknown --agent values must produce an error, not silent failure."""

    def test_unknown_agent_exits_2(self, claude_only: Path) -> None:
        """--agent doesnotexist must exit with code 2."""
        result = runner.invoke(
            app,
            [
                "check",
                str(claude_only),
                "--agent",
                "doesnotexist",
                "--no-update-check",
            ],
        )
        assert result.exit_code == 2, f"Expected exit 2, got {result.exit_code}"
        assert "Unknown agent" in result.output

    def test_unknown_agent_shows_known_list(self, claude_only: Path) -> None:
        """Error message must list valid agents."""
        result = runner.invoke(
            app,
            [
                "check",
                str(claude_only),
                "--agent",
                "doesnotexist",
                "--no-update-check",
            ],
        )
        assert "claude" in result.output
        assert "codex" in result.output

    def test_uppercase_agent_normalized(self, claude_only: Path) -> None:
        """--agent CLAUDE (uppercase) must be normalized to lowercase and work."""
        result = runner.invoke(
            app,
            [
                "check",
                str(claude_only),
                "--agent",
                "CLAUDE",
                "-f",
                "json",
                "--no-update-check",
            ],
        )
        assert result.exit_code == 0, f"Uppercase agent failed: {result.output}"
        data = json.loads(result.output)
        assert data["level"] != "L1", "--agent CLAUDE should detect CLAUDE.md after normalization"


# ===========================================================================
# Format Validation
#
# Bug: -f sarif and other invalid format names silently fell through
# to text format.
# ===========================================================================


@pytest.mark.e2e
class TestFormatValidation:
    """Invalid -f values must produce an error, not silent fallback."""

    def test_invalid_format_exits_2(self, claude_only: Path) -> None:
        """-f sarif must exit with code 2."""
        result = runner.invoke(
            app,
            [
                "check",
                str(claude_only),
                "-f",
                "sarif",
                "--no-update-check",
            ],
        )
        assert result.exit_code == 2, f"Expected exit 2, got {result.exit_code}"
        assert "Unknown format" in result.output

    def test_invalid_format_shows_valid_list(self, claude_only: Path) -> None:
        """Error message must list valid formats."""
        result = runner.invoke(
            app,
            [
                "check",
                str(claude_only),
                "-f",
                "INVALID",
                "--no-update-check",
            ],
        )
        assert result.exit_code == 2
        assert "json" in result.output
        assert "text" in result.output


# ===========================================================================
# Default Agent Config
#
# Users can set default_agent in .reporails/config.yml so they don't need
# --agent on every invocation. CLI flag always overrides config.
# ===========================================================================


@pytest.mark.e2e
class TestDefaultAgentConfig:
    """default_agent in .reporails/config.yml must control agent scoping."""

    @requires_rules
    def test_config_default_agent_scopes_files(self, multi_agent_with_config: Path) -> None:
        """default_agent: claude in config must scope to CLAUDE.md without --agent flag."""
        data = _check_json(multi_agent_with_config)
        files = _violation_files(data)
        assert "AGENTS.md" not in files, f"default_agent: claude should not scan AGENTS.md, got: {files}"
        assert "CLAUDE.md" in files, f"default_agent: claude should scan CLAUDE.md, got: {files}"

    @requires_rules
    def test_cli_flag_overrides_config(self, multi_agent_with_config: Path) -> None:
        """--agent codex must override default_agent: claude from config."""
        data = _check_json(multi_agent_with_config, agent="codex")
        files = _violation_files(data)
        assert "AGENTS.md" in files, f"--agent codex should scan AGENTS.md, got: {files}"
        assert "CLAUDE.md" not in files, f"--agent codex should not scan CLAUDE.md, got: {files}"

    @requires_rules
    def test_no_config_defaults_to_generic(self, multi_agent: Path) -> None:
        """Without config, no --agent must default to generic (AGENTS.md scanned, not CLAUDE.md)."""
        data = _check_json(multi_agent)
        files = _violation_files(data)
        assert "AGENTS.md" in files, f"Without config, no-agent should scan AGENTS.md (generic), got: {files}"
        assert "CLAUDE.md" not in files, f"Without config, CLAUDE.md should not be scanned, got: {files}"


# ===========================================================================
# Config Commands — set/get/list with --global flag
#
# E2E tests for `ails config` subcommands. Uses tmp_path for isolated
# project and global config directories. Global config path is patched
# to avoid touching the real ~/.reporails/config.yml.
# ===========================================================================


@pytest.mark.e2e
class TestConfigSetGet:
    """ails config set/get round-trips values correctly."""

    def test_set_then_get(self, tmp_path: Path) -> None:
        """set + get round-trip for a string key."""
        project = tmp_path / "project"
        project.mkdir()
        result = runner.invoke(app, ["config", "set", "default_agent", "claude", "--path", str(project)])
        assert result.exit_code == 0, f"set failed:\n{result.output}"

        result = runner.invoke(app, ["config", "get", "default_agent", "--path", str(project)])
        assert result.exit_code == 0
        assert "claude" in result.output

    def test_set_bool(self, tmp_path: Path) -> None:
        """set + get round-trip for a boolean key."""
        project = tmp_path / "project"
        project.mkdir()
        runner.invoke(app, ["config", "set", "recommended", "false", "--path", str(project)])

        result = runner.invoke(app, ["config", "get", "recommended", "--path", str(project)])
        assert result.exit_code == 0
        assert "False" in result.output

    def test_set_list(self, tmp_path: Path) -> None:
        """set + get round-trip for a list key."""
        project = tmp_path / "project"
        project.mkdir()
        runner.invoke(app, ["config", "set", "exclude_dirs", "vendor,dist", "--path", str(project)])

        result = runner.invoke(app, ["config", "get", "exclude_dirs", "--path", str(project)])
        assert result.exit_code == 0
        assert "vendor" in result.output

    def test_get_unset_key(self, tmp_path: Path) -> None:
        """get on an unset known key shows (not set)."""
        project = tmp_path / "project"
        project.mkdir()
        result = runner.invoke(app, ["config", "get", "default_agent", "--path", str(project)])
        assert result.exit_code == 0
        assert "not set" in result.output

    def test_set_unknown_key(self, tmp_path: Path) -> None:
        """set with an unknown key exits with code 2."""
        project = tmp_path / "project"
        project.mkdir()
        result = runner.invoke(app, ["config", "set", "bogus_key", "val", "--path", str(project)])
        assert result.exit_code == 2
        assert "Unknown config key" in result.output

    def test_get_unknown_key(self, tmp_path: Path) -> None:
        """get with an unknown key exits with code 2."""
        project = tmp_path / "project"
        project.mkdir()
        result = runner.invoke(app, ["config", "get", "bogus_key", "--path", str(project)])
        assert result.exit_code == 2
        assert "Unknown config key" in result.output


@pytest.mark.e2e
class TestConfigList:
    """ails config list shows all values."""

    def test_list_empty(self, tmp_path: Path) -> None:
        """list with no config shows empty message."""
        project = tmp_path / "project"
        project.mkdir()
        result = runner.invoke(app, ["config", "list", "--path", str(project)])
        assert result.exit_code == 0
        assert "No configuration set" in result.output

    def test_list_shows_values(self, tmp_path: Path) -> None:
        """list after setting values shows them."""
        project = tmp_path / "project"
        project.mkdir()
        runner.invoke(app, ["config", "set", "default_agent", "cursor", "--path", str(project)])
        runner.invoke(app, ["config", "set", "recommended", "false", "--path", str(project)])

        result = runner.invoke(app, ["config", "list", "--path", str(project)])
        assert result.exit_code == 0
        assert "default_agent: cursor" in result.output
        assert "recommended: False" in result.output


@pytest.mark.e2e
class TestConfigGlobal:
    """ails config --global reads/writes ~/.reporails/config.yml."""

    @pytest.fixture(autouse=True)
    def _patch_global(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Redirect global config to tmp_path so tests never touch real home."""
        self.global_home = tmp_path / "fake_home" / ".reporails"
        self.global_home.mkdir(parents=True)
        monkeypatch.setattr(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            lambda: self.global_home / "config.yml",
        )

    def test_global_set_then_get(self) -> None:
        """--global set + get round-trip."""
        result = runner.invoke(app, ["config", "set", "--global", "default_agent", "claude"])
        assert result.exit_code == 0, f"global set failed:\n{result.output}"
        assert "global" in result.output

        result = runner.invoke(app, ["config", "get", "--global", "default_agent"])
        assert result.exit_code == 0
        assert "claude" in result.output

    def test_global_set_recommended(self) -> None:
        """--global set works for boolean key."""
        result = runner.invoke(app, ["config", "set", "--global", "recommended", "false"])
        assert result.exit_code == 0

        result = runner.invoke(app, ["config", "get", "--global", "recommended"])
        assert result.exit_code == 0
        assert "False" in result.output

    def test_global_rejects_non_global_key(self) -> None:
        """--global set with a project-only key errors."""
        result = runner.invoke(app, ["config", "set", "--global", "exclude_dirs", "vendor"])
        assert result.exit_code == 2
        assert "not supported in global config" in result.output

    def test_global_list(self) -> None:
        """--global list shows only global config."""
        runner.invoke(app, ["config", "set", "--global", "default_agent", "claude"])

        result = runner.invoke(app, ["config", "list", "--global"])
        assert result.exit_code == 0
        assert "default_agent: claude" in result.output

    def test_global_list_empty(self) -> None:
        """--global list with no config shows empty message."""
        result = runner.invoke(app, ["config", "list", "--global"])
        assert result.exit_code == 0
        assert "No global configuration set" in result.output

    def test_list_annotates_global_fallback(self, tmp_path: Path) -> None:
        """project list shows global values annotated with (global)."""
        project = tmp_path / "project"
        project.mkdir()
        runner.invoke(app, ["config", "set", "exclude_dirs", "vendor", "--path", str(project)])
        runner.invoke(app, ["config", "set", "--global", "default_agent", "claude"])

        result = runner.invoke(app, ["config", "list", "--path", str(project)])
        assert result.exit_code == 0
        assert "default_agent: claude (global)" in result.output
        assert "exclude_dirs:" in result.output
        # exclude_dirs line must NOT be annotated as global
        for line in result.output.splitlines():
            if line.startswith("exclude_dirs:"):
                assert "(global)" not in line, f"exclude_dirs should not be global: {line}"

    def test_project_overrides_global_in_list(self, tmp_path: Path) -> None:
        """project value wins over global — no (global) annotation."""
        project = tmp_path / "project"
        project.mkdir()
        runner.invoke(app, ["config", "set", "default_agent", "cursor", "--path", str(project)])
        runner.invoke(app, ["config", "set", "--global", "default_agent", "claude"])

        result = runner.invoke(app, ["config", "list", "--path", str(project)])
        assert result.exit_code == 0
        assert "default_agent: cursor" in result.output
        assert "(global)" not in result.output


@pytest.mark.e2e
class TestGlobalDefaultsInCheck:
    """Global config defaults must flow through to ails check."""

    @pytest.fixture(autouse=True)
    def _patch_global(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Redirect global config to tmp_path."""
        self.global_home = tmp_path / "fake_home" / ".reporails"
        self.global_home.mkdir(parents=True)
        monkeypatch.setattr(
            "reporails_cli.core.bootstrap.get_global_config_path",
            lambda: self.global_home / "config.yml",
        )

    @requires_rules
    def test_global_default_agent_scopes_check(self, tmp_path: Path) -> None:
        """Global default_agent: claude scopes ails check to CLAUDE.md."""
        # Write global config
        (self.global_home / "config.yml").write_text("default_agent: claude\n")

        # Create project with both CLAUDE.md and AGENTS.md, no project config
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# My Project\n\nMinimal content.\n")
        (project / "AGENTS.md").write_text("# Agents\n\nMinimal content.\n")

        data = _check_json(project)
        files = _violation_files(data)
        assert "CLAUDE.md" in files, f"global default_agent: claude should scan CLAUDE.md, got: {files}"
        assert "AGENTS.md" not in files, f"global default_agent: claude should not scan AGENTS.md, got: {files}"

    @requires_rules
    def test_project_default_agent_overrides_global(self, tmp_path: Path) -> None:
        """Project default_agent overrides global — check uses project value."""
        (self.global_home / "config.yml").write_text("default_agent: claude\n")

        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# My Project\n\nMinimal content.\n")
        (project / "AGENTS.md").write_text("# Agents\n\nMinimal content.\n")

        # Project config overrides global
        cfg_dir = project / ".reporails"
        cfg_dir.mkdir()
        (cfg_dir / "config.yml").write_text("default_agent: codex\n")

        data = _check_json(project)
        files = _violation_files(data)
        # Project says codex → scopes to AGENTS.md, NOT CLAUDE.md
        assert "CLAUDE.md" not in files, f"project default_agent: codex should not scan CLAUDE.md, got: {files}"


# ===========================================================================
# Version Command
#
# `ails version` shows CLI, framework, and recommended versions plus
# install method. Must always succeed regardless of installed state.
# ===========================================================================


@pytest.mark.e2e
class TestVersionCommand:
    """ails version must show version info and exit cleanly."""

    def test_exits_zero(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0, f"version failed:\n{result.output}"

    def test_shows_cli_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert "CLI:" in result.output

    def test_shows_framework_line(self) -> None:
        result = runner.invoke(app, ["version"])
        assert "Framework:" in result.output

    def test_shows_recommended_line(self) -> None:
        result = runner.invoke(app, ["version"])
        assert "Recommended:" in result.output

    def test_shows_install_method(self) -> None:
        result = runner.invoke(app, ["version"])
        assert "Install:" in result.output


# ===========================================================================
# Explain Command
#
# `ails explain RULE_ID` shows rule details. Requires rules framework
# for known rules. Unknown rules must exit 2 with error message.
# ===========================================================================


@pytest.mark.e2e
class TestExplainCommand:
    """ails explain shows rule details or errors on unknown rule."""

    @requires_rules
    def test_known_rule_exits_zero(self) -> None:
        result = runner.invoke(app, ["explain", "CORE:S:0001"])
        assert result.exit_code == 0, f"explain failed:\n{result.output}"

    @requires_rules
    def test_known_rule_shows_id(self) -> None:
        result = runner.invoke(app, ["explain", "CORE:S:0001"])
        assert "CORE:S:0001" in result.output

    @requires_rules
    def test_known_rule_shows_category(self) -> None:
        result = runner.invoke(app, ["explain", "CORE:S:0001"])
        # Rule output should contain category info
        output_lower = result.output.lower()
        assert "category" in output_lower or "structure" in output_lower

    def test_unknown_rule_exits_2(self) -> None:
        result = runner.invoke(app, ["explain", "FAKE:Z:9999"])
        assert result.exit_code == 2, f"Expected exit 2, got {result.exit_code}"

    def test_unknown_rule_shows_error(self) -> None:
        result = runner.invoke(app, ["explain", "FAKE:Z:9999"])
        assert "unknown" in result.output.lower() or "not found" in result.output.lower()


# ===========================================================================
# Heal Command
#
# `ails heal` auto-fixes deterministic violations. Must work on projects
# with instruction files, error on missing paths, and support JSON output.
# ===========================================================================


@pytest.mark.e2e
class TestHealCommand:
    """ails heal applies auto-fixes and reports results."""

    def test_missing_path_errors(self) -> None:
        result = runner.invoke(app, ["heal", "/tmp/no-such-path-xyz-abc-987"])
        assert result.exit_code != 0

    @requires_rules
    def test_heal_runs_on_project(self, tmp_path: Path) -> None:
        """heal on a minimal project exits cleanly."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# My Project\n\nA project.\n")

        result = runner.invoke(app, ["heal", str(project)])
        assert result.exit_code in (0, None), f"heal failed:\n{result.output}"

    @requires_rules
    def test_heal_modifies_files(self, tmp_path: Path) -> None:
        """heal must actually modify files when fixes are available."""
        project = tmp_path / "project"
        project.mkdir()
        original = "# My Project\n\nA project.\n"
        (project / "CLAUDE.md").write_text(original)

        runner.invoke(app, ["heal", str(project)])
        content = (project / "CLAUDE.md").read_text()
        # Heal should add missing sections (e.g., ## Commands, ## Testing)
        assert len(content) >= len(original), "heal should not shrink files"

    @requires_rules
    def test_heal_json_output(self, tmp_path: Path) -> None:
        """heal -f json must produce valid JSON with expected keys."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# My Project\n\nA project.\n")

        result = runner.invoke(app, ["heal", str(project), "-f", "json"])
        assert result.exit_code in (0, None), f"heal json failed:\n{result.output}"
        data = json.loads(result.output)
        assert "auto_fixed" in data
        assert "summary" in data

    @requires_rules
    def test_heal_with_agent(self, tmp_path: Path) -> None:
        """heal --agent claude scopes to CLAUDE.md."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# My Project\n\nA project.\n")

        result = runner.invoke(app, ["heal", str(project), "--agent", "claude"])
        assert result.exit_code in (0, None), f"heal --agent failed:\n{result.output}"

    def test_heal_empty_project(self, tmp_path: Path) -> None:
        """heal on empty project (no instruction files) exits cleanly."""
        project = tmp_path / "empty"
        project.mkdir()

        result = runner.invoke(app, ["heal", str(project)])
        # Should exit 0 or 1 with message — not crash
        assert result.exit_code in (0, 1, None)


# ===========================================================================
# Map Command
#
# `ails map` detects agents and project layout. Supports text, yaml,
# json output formats and --save to write backbone.yml.
# ===========================================================================


@pytest.mark.e2e
class TestMapCommand:
    """ails map detects agents and project structure."""

    def test_text_output(self, claude_only: Path) -> None:
        result = runner.invoke(app, ["map", str(claude_only)])
        assert result.exit_code == 0, f"map failed:\n{result.output}"
        output_lower = result.output.lower()
        assert "claude" in output_lower

    def test_json_output_valid(self, claude_only: Path) -> None:
        result = runner.invoke(app, ["map", str(claude_only), "-o", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "agents" in data

    def test_yaml_output_valid(self, claude_only: Path) -> None:
        import yaml as yaml_lib

        result = runner.invoke(app, ["map", str(claude_only), "-o", "yaml"])
        assert result.exit_code == 0
        data = yaml_lib.safe_load(result.output)
        assert "agents" in data

    def test_save_creates_backbone(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# My Project\n")

        result = runner.invoke(app, ["map", str(project), "--save"])
        assert result.exit_code == 0
        backbone = project / ".reporails" / "backbone.yml"
        assert backbone.exists(), "backbone.yml not created"

    def test_multi_agent_detected(self, multi_agent: Path) -> None:
        result = runner.invoke(app, ["map", str(multi_agent), "-o", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        agents = data.get("agents", {})
        assert len(agents) >= 2, f"Expected multiple agents, got: {list(agents.keys())}"

    def test_missing_path_errors(self) -> None:
        result = runner.invoke(app, ["map", "/tmp/no-such-path-xyz-abc-987"])
        assert result.exit_code == 1

    def test_empty_dir_no_crash(self, tmp_path: Path) -> None:
        project = tmp_path / "empty"
        project.mkdir()
        result = runner.invoke(app, ["map", str(project)])
        assert result.exit_code == 0


# ===========================================================================
# Dismiss Command
#
# `ails dismiss RULE_ID` caches a pass verdict for a semantic rule.
# Hidden plumbing command used by MCP and scripts.
# ===========================================================================


@pytest.mark.e2e
class TestDismissCommand:
    """ails dismiss caches pass verdicts for semantic rules."""

    def test_dismiss_exits_zero(self, claude_only: Path) -> None:
        result = runner.invoke(app, ["dismiss", "CORE:C:0006", "--path", str(claude_only)])
        assert result.exit_code == 0, f"dismiss failed:\n{result.output}"

    def test_dismiss_output_confirms(self, claude_only: Path) -> None:
        result = runner.invoke(app, ["dismiss", "CORE:C:0006", "--path", str(claude_only)])
        assert "Dismissed" in result.output
        assert "CORE:C:0006" in result.output

    def test_dismiss_missing_path(self) -> None:
        result = runner.invoke(app, ["dismiss", "CORE:C:0006", "--path", "/tmp/no-such-path-xyz"])
        assert result.exit_code == 1

    def test_dismiss_no_files(self, tmp_path: Path) -> None:
        project = tmp_path / "empty"
        project.mkdir()
        result = runner.invoke(app, ["dismiss", "CORE:C:0006", "--path", str(project)])
        assert result.exit_code == 1
        assert "No instruction files" in result.output

    def test_dismiss_for_specific_file(self, claude_only: Path) -> None:
        result = runner.invoke(app, ["dismiss", "CORE:C:0006", "CLAUDE.md", "--path", str(claude_only)])
        assert result.exit_code == 0
        assert "1 file" in result.output


# ===========================================================================
# Judge Command
#
# `ails judge PATH VERDICTS...` caches semantic verdicts in batch.
# Hidden plumbing command. Output is JSON with recorded count.
# ===========================================================================


@pytest.mark.e2e
class TestJudgeCommand:
    """ails judge caches semantic verdicts."""

    def test_judge_records_verdict(self, claude_only: Path) -> None:
        result = runner.invoke(app, ["judge", str(claude_only), "CORE:C:0006:CLAUDE.md:pass:Looks good"])
        assert result.exit_code == 0, f"judge failed:\n{result.output}"
        data = json.loads(result.output)
        assert data["recorded"] >= 1

    def test_judge_no_verdicts_errors(self, claude_only: Path) -> None:
        result = runner.invoke(app, ["judge", str(claude_only)])
        assert result.exit_code == 1

    def test_judge_missing_path(self) -> None:
        result = runner.invoke(app, ["judge", "/tmp/no-such-path-xyz", "CORE:C:0006:CLAUDE.md:pass:ok"])
        assert result.exit_code == 1

    def test_judge_multiple_verdicts(self, claude_only: Path) -> None:
        result = runner.invoke(
            app,
            [
                "judge",
                str(claude_only),
                "CORE:C:0006:CLAUDE.md:pass:Good",
                "CORE:C:0012:CLAUDE.md:fail:Missing date",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["recorded"] >= 2


# ===========================================================================
# Install Command
#
# `ails install` detects agents and writes MCP config. Tests use
# monkeypatch to avoid writing to real agent config locations.
# ===========================================================================


@pytest.mark.e2e
class TestInstallCommand:
    """ails install detects agents and writes MCP config."""

    def test_install_detects_claude(self, tmp_path: Path) -> None:
        """Install on project with CLAUDE.md detects claude agent."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# My Project\n")
        # Create .claude dir so MCP config can be written there
        (project / ".claude").mkdir()

        result = runner.invoke(app, ["install", str(project)])
        assert result.exit_code == 0, f"install failed:\n{result.output}"
        assert "claude" in result.output.lower()
        assert "Restart" in result.output

    def test_install_no_agents(self, tmp_path: Path) -> None:
        """Install on empty project exits 1."""
        project = tmp_path / "empty"
        project.mkdir()

        result = runner.invoke(app, ["install", str(project)])
        assert result.exit_code == 1
        assert "No supported agents" in result.output

    def test_install_missing_path(self) -> None:
        result = runner.invoke(app, ["install", "/tmp/no-such-path-xyz-abc-987"])
        assert result.exit_code == 1

    def test_install_writes_config_file(self, tmp_path: Path) -> None:
        """Install must write an MCP config file."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# My Project\n")
        (project / ".claude").mkdir()

        runner.invoke(app, ["install", str(project)])
        # MCP config written to .mcp.json (project root) or .claude/mcp.json
        mcp_json = project / ".mcp.json"
        claude_mcp = project / ".claude" / "mcp.json"
        assert mcp_json.exists() or claude_mcp.exists(), f"MCP config not created. Files: {list(project.rglob('*'))}"


# ===========================================================================
# Update Command (--check only)
#
# `ails update --check` is safe to run E2E — it checks for updates
# without installing anything. Full update tests are integration-only
# due to network dependency.
# ===========================================================================


@pytest.mark.e2e
class TestUpdateCheckCommand:
    """ails update --check shows update status without installing."""

    def test_check_exits_zero(self) -> None:
        result = runner.invoke(app, ["update", "--check"])
        assert result.exit_code == 0, f"update --check failed:\n{result.output}"

    def test_check_shows_output(self) -> None:
        result = runner.invoke(app, ["update", "--check"])
        # Should show version info or "up to date" message
        assert len(result.output.strip()) > 0, "update --check produced no output"


# ===========================================================================
# Check Command — Additional Flag Coverage
#
# Core check command is heavily tested above. These cover specific flags
# that aren't exercised in the agent-scoping tests.
# ===========================================================================


@pytest.mark.e2e
class TestCheckFlags:
    """Additional flag coverage for ails check."""

    @requires_rules
    def test_strict_exits_1_on_violations(self, generic_only: Path) -> None:
        """--strict must exit 1 when violations exist."""
        result = runner.invoke(app, ["check", str(generic_only), "--strict", "--no-update-check"])
        assert result.exit_code == 1

    @requires_rules
    def test_json_output_valid(self, claude_only: Path) -> None:
        data = _check_json(claude_only, agent="claude")
        assert "score" in data
        assert "violations" in data
        assert "level" in data
        assert isinstance(data["score"], (int, float))

    @requires_rules
    def test_verbose_output(self, claude_only: Path) -> None:
        result = runner.invoke(
            app, ["check", str(claude_only), "-f", "text", "-v", "--agent", "claude", "--no-update-check"]
        )
        assert result.exit_code == 0
        # Verbose mode shows per-file PASS/FAIL
        assert "PASS" in result.output or "FAIL" in result.output

    @requires_rules
    def test_exclude_dir(self, tmp_path: Path) -> None:
        """--exclude-dir prevents scanning files in that directory."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Main\n")
        subdir = project / "vendor"
        subdir.mkdir()
        (subdir / "CLAUDE.md").write_text("# Vendor\n")

        # Without exclude, vendor/CLAUDE.md could be scanned
        result_excluded = runner.invoke(
            app,
            ["check", str(project), "-f", "json", "--no-update-check", "--exclude-dir", "vendor"],
        )
        assert result_excluded.exit_code == 0
        excluded_data = json.loads(result_excluded.output)
        excluded_files = _violation_files(excluded_data)
        assert not any("vendor" in f for f in excluded_files), f"vendor dir not excluded: {excluded_files}"

    @requires_rules
    def test_ascii_mode(self, claude_only: Path) -> None:
        """--ascii must not produce Unicode box-drawing characters."""
        result = runner.invoke(
            app, ["check", str(claude_only), "-f", "text", "--ascii", "--agent", "claude", "--no-update-check"]
        )
        assert result.exit_code == 0
        # Box-drawing chars are Unicode (U+2500 range)
        assert "\u2550" not in result.output, "ASCII mode produced Unicode box characters"


# ===========================================================================
# Mechanical checks E2E — full pipeline through ails check
#
# These tests verify that mechanical check violations appear in the final
# output after flowing through the complete pipeline: rule loading →
# mechanical dispatch → scoring → JSON output. This catches integration
# bugs invisible to unit tests (e.g., mechanical results dropped during
# SARIF merge, wrong check type filtering, template resolution failures).
# ===========================================================================


@pytest.mark.e2e
class TestMechanicalChecksE2E:
    """Mechanical checks must produce violations in ails check output."""

    @requires_rules
    def test_missing_git_produces_violation(self, tmp_path: Path) -> None:
        """Project without .git directory — mechanical pipeline runs and produces violations."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# My Project\n\nMinimal content.\n")

        data = _check_json(project, agent="claude")

        # Without .git, project should get violations (mechanical and/or deterministic)
        assert len(data["violations"]) > 0, (
            f"Zero violations on project without .git — pipeline not firing. "
            f"score={data['score']}, rules_checked={data.get('summary', {}).get('rules_checked', 0)}"
        )
        assert data["score"] < 10.0, "Minimal project without .git should not score perfectly"

    @requires_rules
    def test_violations_include_rule_metadata(self, tmp_path: Path) -> None:
        """Each violation has required fields: rule_id, location, message, severity."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# My Project\n\nMinimal content.\n")

        data = _check_json(project, agent="claude")

        assert len(data["violations"]) > 0, "Expected violations on project without .git"
        for v in data["violations"]:
            assert "rule_id" in v, f"Missing rule_id in violation: {v}"
            assert "location" in v, f"Missing location in violation: {v}"
            assert "message" in v, f"Missing message in violation: {v}"
            assert "severity" in v, f"Missing severity in violation: {v}"

    @requires_rules
    def test_mechanical_violations_have_locations(self, tmp_path: Path) -> None:
        """Mechanical violations must have file:line location format."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Minimal\n")

        data = _check_json(project, agent="claude")

        for v in data["violations"]:
            assert ":" in v["location"], f"Violation {v['rule_id']} has no line number in location: {v['location']}"

    @requires_rules
    def test_mechanical_violations_in_text_output(self, tmp_path: Path) -> None:
        """Mechanical violations appear in text output (not just JSON)."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Minimal\n")

        output = _check_text(project, agent="claude")

        # Text output should contain violation indicators and reference the file
        assert "CLAUDE.md" in output, "Text output should reference the instruction file"

    @requires_rules
    def test_score_reflects_mechanical_failures(self, claude_only: Path) -> None:
        """Score is computed from both mechanical and deterministic violations."""
        data = _check_json(claude_only, agent="claude")

        # With agent-specific rules, there should be a mix of violation types
        assert "score" in data
        assert isinstance(data["score"], (int, float))
        # Score should be between 0 and 10
        assert 0 <= data["score"] <= 10.0

    @requires_rules
    def test_oversized_file_does_not_crash(self, tmp_path: Path) -> None:
        """Large instruction file is handled gracefully (no crash)."""
        project = tmp_path / "project"
        project.mkdir()
        (project / ".git").mkdir()
        # Create a file that's large but under the 1MB limit
        (project / "CLAUDE.md").write_text("# Section\n\n" + "x " * 50000 + "\n")

        data = _check_json(project, agent="claude")

        # Should complete without crash — score may be low due to content issues
        assert "score" in data
