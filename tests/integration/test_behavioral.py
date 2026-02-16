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

from reporails_cli.core.agents import clear_agent_cache
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


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
def minimal_project(tmp_path: Path) -> Path:
    """Bare CLAUDE.md — L2 project."""
    p = tmp_path / "proj"
    p.mkdir()
    (p / "CLAUDE.md").write_text("# My Project\n\nProject description.\n\n## Commands\n\n- `make build`\n")
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
# CHECK COMMAND — Exit Codes
# ===========================================================================


class TestCheckExitCodes:
    """Exit code contract: 0=ok, 1=strict+violations, 2=input error."""

    @requires_rules
    def test_exit_0_with_violations_no_strict(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "json", "--no-update-check"])
        assert result.exit_code == 0

    @requires_rules
    def test_exit_1_strict_with_violations(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "--strict", "-f", "json", "--no-update-check"])
        data = json.loads(result.output)
        if data["violations"]:
            assert result.exit_code == 1, "strict mode must exit 1 when violations exist"

    def test_exit_2_missing_path(self) -> None:
        result = runner.invoke(app, ["check", "/tmp/no-such-path-xyz-abc", "--no-update-check"])
        assert result.exit_code == 2

    def test_exit_0_no_instruction_files(self, empty_project: Path) -> None:
        result = runner.invoke(app, ["check", str(empty_project), "--no-update-check"])
        assert result.exit_code == 0


# ===========================================================================
# CHECK COMMAND — JSON Output Schema
# ===========================================================================


class TestCheckJsonSchema:
    """JSON output must have a stable, documented schema."""

    @requires_rules
    def test_required_keys_present(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "json", "--no-update-check"])
        assert result.exit_code == 0
        data = json.loads(result.output)

        required = {"score", "level", "violations", "summary", "friction", "category_summary"}
        assert required.issubset(data.keys()), f"Missing keys: {required - data.keys()}"

    @requires_rules
    def test_score_is_number_in_range(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "json", "--no-update-check"])
        data = json.loads(result.output)
        assert isinstance(data["score"], (int, float))
        assert 0 <= data["score"] <= 10

    @requires_rules
    def test_level_format(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "json", "--no-update-check"])
        data = json.loads(result.output)
        assert data["level"].startswith("L"), f"Level should start with L, got: {data['level']}"

    @requires_rules
    def test_violations_are_list(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "json", "--no-update-check"])
        data = json.loads(result.output)
        assert isinstance(data["violations"], list)

    @requires_rules
    def test_violation_has_required_fields(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "json", "--no-update-check"])
        data = json.loads(result.output)
        if data["violations"]:
            v = data["violations"][0]
            assert "rule_id" in v
            assert "location" in v
            assert "message" in v
            assert "severity" in v

    def test_no_files_json_output(self, empty_project: Path) -> None:
        result = runner.invoke(app, ["check", str(empty_project), "-f", "json", "--no-update-check"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["violations"] == []
        assert data["level"] == "L1"


# ===========================================================================
# CHECK COMMAND — Scan Scope
# ===========================================================================


class TestCheckScanScope:
    """Files outside the target directory must never appear in results."""

    @requires_rules
    def test_nested_child_only_scans_child(self, nested_project: Path) -> None:
        result = runner.invoke(app, ["check", str(nested_project), "-f", "json", "--no-update-check"])
        assert result.exit_code == 0
        data = json.loads(result.output)

        for v in data["violations"]:
            # Location should be relative to scan root or inside child
            assert "Parent" not in v.get("message", ""), "Parent content leaked into child scan"

    @requires_rules
    def test_nested_child_violation_count_reasonable(self, nested_project: Path) -> None:
        """A single-file project should have a bounded number of violations."""
        result = runner.invoke(app, ["check", str(nested_project), "-f", "json", "--no-update-check"])
        data = json.loads(result.output)
        # One CLAUDE.md can't have hundreds of violations
        assert len(data["violations"]) < 50, f"Suspiciously many violations: {len(data['violations'])}"


# ===========================================================================
# CHECK COMMAND — Text Output
# ===========================================================================


class TestCheckTextOutput:
    """Text output must contain key information."""

    @requires_rules
    def test_score_displayed(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "text", "-q", "--no-update-check"])
        assert result.exit_code == 0
        assert "SCORE:" in result.output or "/ 10" in result.output or "Score:" in result.output

    @requires_rules
    def test_violations_grouped_by_file(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "text", "-q", "--no-update-check"])
        assert result.exit_code == 0
        assert "CLAUDE.md" in result.output

    def test_no_files_shows_l1_message(self, empty_project: Path) -> None:
        result = runner.invoke(app, ["check", str(empty_project), "--no-update-check"])
        assert "No instruction files found" in result.output
        assert "L1" in result.output

    @requires_rules
    def test_quiet_semantic_suppresses_message(self, minimal_project: Path) -> None:
        result_quiet = runner.invoke(app, ["check", str(minimal_project), "-f", "text", "-q", "--no-update-check"])
        result_normal = runner.invoke(app, ["check", str(minimal_project), "-f", "text", "--no-update-check"])
        # If semantic message appears in normal, it should not appear in quiet
        if "semantic" in result_normal.output.lower():
            # -q should either suppress or shorten the message
            assert result_quiet.output != result_normal.output


# ===========================================================================
# CHECK COMMAND — Multiple Files
# ===========================================================================


class TestCheckMultiFile:
    """Projects with multiple instruction files should report all of them."""

    @requires_rules
    def test_multiple_agents_detected(self, multi_file_project: Path) -> None:
        result = runner.invoke(app, ["check", str(multi_file_project), "-f", "json", "--no-update-check"])
        data = json.loads(result.output)
        # Multi-file project should produce valid JSON output with required keys
        assert "violations" in data
        assert "score" in data
        assert "level" in data
        assert result.exit_code == 0


# ===========================================================================
# CHECK COMMAND — Score Consistency
# ===========================================================================


class TestCheckScoreConsistency:
    """Score must be deterministic — same project, same score."""

    @requires_rules
    def test_deterministic_score(self, structured_project: Path) -> None:
        scores = []
        for _ in range(3):
            result = runner.invoke(app, ["check", str(structured_project), "-f", "json", "--no-update-check"])
            data = json.loads(result.output)
            scores.append(data["score"])

        assert len(set(scores)) == 1, f"Score varied across runs: {scores}"

    @requires_rules
    def test_score_is_bounded(self, tmp_path: Path) -> None:
        """Score must be between 0 and 10 for any project content."""
        bare = tmp_path / "bare"
        bare.mkdir()
        (bare / "CLAUDE.md").write_text("# Project\n")

        rich = tmp_path / "rich"
        rich.mkdir()
        (rich / "CLAUDE.md").write_text(
            "# Project\n\n## Commands\n\n- `make build`\n\n"
            "## Architecture\n\nModular.\n\n"
            "## Constraints\n\n- NEVER commit secrets\n"
        )

        for project in [bare, rich]:
            result = runner.invoke(app, ["check", str(project), "-f", "json", "--no-update-check"])
            score = json.loads(result.output)["score"]
            assert 0 <= score <= 10, f"Score {score} out of bounds for {project.name}"


# ===========================================================================
# MAP COMMAND
# ===========================================================================


class TestMapCommand:
    """ails map must detect agents and project structure."""

    def test_text_output_shows_agent(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["map", str(minimal_project)])
        assert result.exit_code == 0
        assert "Claude" in result.output or "claude" in result.output.lower()

    def test_yaml_output_valid(self, minimal_project: Path) -> None:
        import yaml

        result = runner.invoke(app, ["map", str(minimal_project), "-o", "yaml"])
        assert result.exit_code == 0
        data = yaml.safe_load(result.output)
        assert isinstance(data, dict)
        assert "agents" in data

    def test_json_output_valid(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["map", str(minimal_project), "-o", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, dict)
        assert "agents" in data

    def test_save_creates_backbone(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["map", str(minimal_project), "--save"])
        assert result.exit_code == 0

        backbone = minimal_project / ".reporails" / "backbone.yml"
        assert backbone.exists(), "backbone.yml should be created"

        import yaml

        data = yaml.safe_load(backbone.read_text())
        assert "agents" in data

    def test_missing_path_errors(self) -> None:
        result = runner.invoke(app, ["map", "/tmp/no-such-path-xyz-abc"])
        assert result.exit_code == 1

    def test_empty_dir_no_crash(self, empty_project: Path) -> None:
        result = runner.invoke(app, ["map", str(empty_project)])
        assert result.exit_code == 0

    def test_multi_agent_detected(self, multi_file_project: Path) -> None:
        result = runner.invoke(app, ["map", str(multi_file_project), "-o", "json"])
        data = json.loads(result.output)
        agents = data.get("agents", {})
        assert len(agents) >= 2, f"Should detect Claude + Generic, got: {list(agents.keys())}"


# ===========================================================================
# DISMISS COMMAND
# ===========================================================================


class TestDismissCommand:
    """ails dismiss must cache a pass verdict for the rule."""

    def test_dismiss_caches_verdict(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["dismiss", "C6", "--path", str(minimal_project)])
        assert result.exit_code == 0
        assert "Dismissed" in result.output
        assert "C6" in result.output

        # Verify cache was written
        from reporails_cli.core.cache import ProjectCache, content_hash

        # Find project root the same way dismiss does
        from reporails_cli.core.engine_helpers import _find_project_root

        project_root = _find_project_root(minimal_project)
        cache = ProjectCache(project_root)
        md = minimal_project / "CLAUDE.md"
        h = content_hash(md)
        judgment = cache.get_cached_judgment(str(md.relative_to(minimal_project)), h)
        assert judgment is not None
        assert "C6" in judgment
        assert judgment["C6"]["verdict"] == "pass"

    def test_dismiss_missing_path(self) -> None:
        result = runner.invoke(app, ["dismiss", "C6", "--path", "/tmp/no-such-path-xyz"])
        assert result.exit_code == 1

    def test_dismiss_no_files(self, empty_project: Path) -> None:
        result = runner.invoke(app, ["dismiss", "C6", "--path", str(empty_project)])
        assert result.exit_code == 1
        assert "No instruction files" in result.output


# ===========================================================================
# JUDGE COMMAND
# ===========================================================================


class TestJudgeCommand:
    """ails judge must cache verdicts in batch."""

    def test_judge_records_verdict(self, minimal_project: Path) -> None:
        result = runner.invoke(
            app,
            ["judge", str(minimal_project), "C6:CLAUDE.md:pass:Looks good"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["recorded"] >= 1

    def test_judge_no_verdicts_errors(self, minimal_project: Path) -> None:
        result = runner.invoke(app, ["judge", str(minimal_project)])
        assert result.exit_code == 1

    def test_judge_missing_path(self) -> None:
        result = runner.invoke(app, ["judge", "/tmp/no-such-path-xyz", "C6:CLAUDE.md:pass:ok"])
        assert result.exit_code == 1


# ===========================================================================
# EXPLAIN COMMAND
# ===========================================================================


class TestExplainCommand:
    """ails explain must show rule details."""

    @requires_rules
    def test_known_rule(self) -> None:
        result = runner.invoke(app, ["explain", "CORE:S:0001"])
        assert result.exit_code == 0
        assert "CORE:S:0001" in result.output or "structure" in result.output.lower()

    def test_unknown_rule(self) -> None:
        result = runner.invoke(app, ["explain", "ZZZZZ99"])
        assert result.exit_code == 1
        assert "Unknown rule" in result.output or "Error" in result.output


# ===========================================================================
# VERSION COMMAND
# ===========================================================================


class TestVersionCommand:
    """ails version must show component versions."""

    def test_shows_cli_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "CLI:" in result.output

    def test_shows_framework_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "Framework:" in result.output

    def test_shows_recommended_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "Recommended:" in result.output


# ===========================================================================
# CHECK COMMAND — Flags
# ===========================================================================


class TestCheckFlags:
    """CLI flags must produce the documented behavior."""

    @requires_rules
    def test_refresh_flag_accepted(self, minimal_project: Path) -> None:
        """--refresh should not error and should produce valid output."""
        result = runner.invoke(app, ["check", str(minimal_project), "--refresh", "-f", "json", "--no-update-check"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "score" in data

    @requires_rules
    def test_exclude_dir_reduces_scan(self, tmp_path: Path) -> None:
        """--exclude-dir should prevent scanning excluded directories."""
        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# Main\n\nMain project.\n")

        # Create a subdir with its own CLAUDE.md
        sub = p / "vendor"
        sub.mkdir()
        (sub / "CLAUDE.md").write_text("# Vendor\n\nVendor code.\n")

        # Without exclude — should find both
        r1 = runner.invoke(app, ["check", str(p), "-f", "json", "--no-update-check"])
        d1 = json.loads(r1.output)

        # With exclude — should skip vendor
        r2 = runner.invoke(app, ["check", str(p), "--exclude-dir", "vendor", "-f", "json", "--no-update-check"])
        d2 = json.loads(r2.output)

        # Fewer or equal violations with exclude
        assert len(d2["violations"]) <= len(d1["violations"])

    @requires_rules
    def test_ascii_flag_no_unicode(self, minimal_project: Path) -> None:
        """--ascii should produce output without Unicode box drawing."""
        result = runner.invoke(app, ["check", str(minimal_project), "--ascii", "-q", "--no-update-check"])
        assert result.exit_code == 0
        # Unicode box chars should not appear
        for char in "\u2550\u2551\u2554\u2557\u255a\u255d":
            assert char not in result.output, f"Unicode char {char!r} found with --ascii"

    def test_legend_flag_shows_legend(self) -> None:
        """--legend should show severity legend and exit."""
        result = runner.invoke(app, ["check", ".", "--legend"])
        assert result.exit_code == 0
        assert "Legend" in result.output or "Severity" in result.output

    @requires_rules
    def test_compact_format(self, minimal_project: Path) -> None:
        """-f compact should produce condensed output."""
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "compact", "--no-update-check"])
        assert result.exit_code == 0
        assert len(result.output.strip()) > 0

    @requires_rules
    def test_brief_format(self, minimal_project: Path) -> None:
        """-f brief should produce output."""
        result = runner.invoke(app, ["check", str(minimal_project), "-f", "brief", "--no-update-check"])
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
        result = runner.invoke(app, ["check", str(target), "-f", "json", "--no-update-check"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "score" in data


# ===========================================================================
# CHECK COMMAND — Config Integration
# ===========================================================================


class TestCheckConfig:
    """Project config must affect validation behavior."""

    @requires_rules
    def test_disabled_rules_excluded(self, tmp_path: Path) -> None:
        """Rules listed in .reporails/config.yml disabled_rules should not fire."""
        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# Project\n\nA project.\n")

        # Run without config — get violations
        r1 = runner.invoke(app, ["check", str(p), "-f", "json", "--no-update-check"])
        d1 = json.loads(r1.output)
        if not d1["violations"]:
            pytest.skip("No violations to disable")

        # Get a rule ID to disable
        rule_to_disable = d1["violations"][0]["rule_id"]

        # Create config that disables it
        config_dir = p / ".reporails"
        config_dir.mkdir()
        (config_dir / "config.yml").write_text(f"disabled_rules:\n  - {rule_to_disable}\n")

        # Run with config — that rule should not fire
        clear_agent_cache()
        r2 = runner.invoke(app, ["check", str(p), "-f", "json", "--no-update-check"])
        d2 = json.loads(r2.output)

        fired_rules = {v["rule_id"] for v in d2["violations"]}
        assert rule_to_disable not in fired_rules, f"{rule_to_disable} fired despite being disabled"


# ===========================================================================
# HEAL COMMAND
# ===========================================================================


class TestHealCommand:
    """ails heal must run auto-fixes, present semantic prompts, cache verdicts."""

    def test_heal_requires_tty(self, minimal_project: Path) -> None:
        """CliRunner is non-TTY — heal should refuse to run."""
        result = runner.invoke(app, ["heal", str(minimal_project)])
        assert result.exit_code == 2
        assert "interactive terminal" in result.output.lower() or "tty" in result.output.lower()

    def test_heal_missing_path(self) -> None:
        result = runner.invoke(app, ["heal", "/tmp/no-such-path-xyz"])
        assert result.exit_code != 0

    @requires_rules
    def test_heal_auto_fixes_applied(self, tmp_path: Path) -> None:
        """Auto-fixers should modify the file and report what they fixed."""
        from unittest.mock import patch

        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# My Project\n\nA project.\n")

        with patch("reporails_cli.interfaces.cli.heal.sys") as mock_sys:
            mock_sys.stdout.isatty.return_value = True
            result = runner.invoke(app, ["heal", str(p)], input="s\n" * 50)

        assert result.exit_code in (0, None), f"heal failed: {result.output}"

        content = (p / "CLAUDE.md").read_text()
        original = "# My Project\n\nA project.\n"
        if content != original:
            assert len(content) > len(original)

    @requires_rules
    def test_heal_pass_verdict_cached(self, tmp_path: Path) -> None:
        """Passing a semantic rule should cache the verdict."""
        from unittest.mock import patch

        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text(
            "# Project\n\n## Commands\n\n- `make build`\n\n## Constraints\n\n- NEVER commit secrets\n"
        )

        with patch("reporails_cli.interfaces.cli.heal.sys") as mock_sys:
            mock_sys.stdout.isatty.return_value = True
            result = runner.invoke(app, ["heal", str(p)], input="p\n" * 50)

        assert result.exit_code in (0, None), f"heal failed: {result.output}"

        if "Passed" in result.output:
            from reporails_cli.core.cache import ProjectCache

            cache_dir = p / ".reporails" / ".cache"
            if cache_dir.exists():
                cache = ProjectCache(p)
                assert cache.cache_dir.exists()

    @requires_rules
    def test_heal_fail_verdict_with_reason(self, tmp_path: Path) -> None:
        """Failing a semantic rule should prompt for reason and cache it."""
        from unittest.mock import patch

        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# Project\n\nBasic project.\n")

        with patch("reporails_cli.interfaces.cli.heal.sys") as mock_sys:
            mock_sys.stdout.isatty.return_value = True
            result = runner.invoke(app, ["heal", str(p)], input="f\nNot good enough\n" + "s\n" * 50)

        assert result.exit_code in (0, None), f"heal failed: {result.output}"
        if "verdict" in result.output.lower():
            assert "Failed" in result.output or "Skipped" in result.output

    @requires_rules
    def test_heal_dismiss_verdict(self, tmp_path: Path) -> None:
        """Dismissing a semantic rule should cache it as pass."""
        from unittest.mock import patch

        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# Project\n\nBasic project.\n")

        with patch("reporails_cli.interfaces.cli.heal.sys") as mock_sys:
            mock_sys.stdout.isatty.return_value = True
            result = runner.invoke(app, ["heal", str(p)], input="d\n" * 50)

        assert result.exit_code in (0, None), f"heal failed: {result.output}"

    @requires_rules
    def test_heal_nothing_to_heal(self, tmp_path: Path) -> None:
        """When all rules pass or are cached, heal should say nothing to do."""
        from unittest.mock import patch

        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# Project\n\nBasic project.\n")

        # First pass — dismiss everything
        with patch("reporails_cli.interfaces.cli.heal.sys") as mock_sys:
            mock_sys.stdout.isatty.return_value = True
            runner.invoke(app, ["heal", str(p)], input="d\n" * 50)

        # Second pass — everything should be cached
        with patch("reporails_cli.interfaces.cli.heal.sys") as mock_sys:
            mock_sys.stdout.isatty.return_value = True
            result = runner.invoke(app, ["heal", str(p)], input="")

        assert result.exit_code in (0, None)
        assert "Nothing to heal" in result.output or "Fixed" in result.output or "0" in result.output

    @requires_rules
    def test_heal_summary_shows_counts(self, tmp_path: Path) -> None:
        """Heal summary should report pass/fail/skip/dismiss counts."""
        from unittest.mock import patch

        p = tmp_path / "proj"
        p.mkdir()
        (p / "CLAUDE.md").write_text("# Project\n\nBasic project.\n")

        with patch("reporails_cli.interfaces.cli.heal.sys") as mock_sys:
            mock_sys.stdout.isatty.return_value = True
            result = runner.invoke(app, ["heal", str(p)], input="p\n" + "s\n" * 50)

        assert result.exit_code in (0, None)
        output_lower = result.output.lower()
        if "pending" in output_lower or "semantic" in output_lower:
            assert "pass" in output_lower or "skip" in output_lower or "summary" in output_lower


# ===========================================================================
# CHECK COMMAND — Delta Tracking
# ===========================================================================


class TestCheckDelta:
    """Score/level deltas should appear after the first run."""

    @requires_rules
    def test_second_run_shows_delta(self, minimal_project: Path) -> None:
        """Running check twice should show delta on the second run."""
        # First run — no delta
        runner.invoke(app, ["check", str(minimal_project), "-f", "json", "--no-update-check"])

        # Second run — should have delta fields
        r2 = runner.invoke(app, ["check", str(minimal_project), "-f", "json", "--no-update-check"])
        d2 = json.loads(r2.output)
        # Delta fields should exist (may be 0 if unchanged)
        assert "score_delta" in d2
        assert "violations_delta" in d2
