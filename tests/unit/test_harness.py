"""Unit tests for core.harness — rule harness engine."""

from __future__ import annotations

from pathlib import Path

# ── Helpers ──────────────────────────────────────────────────────────


def _make_rule_dir(tmp_path: Path, slug: str, frontmatter: str, body: str = "") -> Path:
    """Create a minimal rule directory with rule.md."""
    rule_dir = tmp_path / "core" / "structure" / slug
    rule_dir.mkdir(parents=True)
    (rule_dir / "rule.md").write_text(f"---\n{frontmatter}\n---\n\n{body}")
    return rule_dir


def _make_fixtures(rule_dir: Path, pass_content: str | None, fail_content: str | None) -> None:
    """Create pass/fail fixture files in a rule directory."""
    if pass_content is not None:
        pass_dir = rule_dir / "tests" / "pass"
        pass_dir.mkdir(parents=True)
        (pass_dir / "CLAUDE.md").write_text(pass_content)
    if fail_content is not None:
        fail_dir = rule_dir / "tests" / "fail"
        fail_dir.mkdir(parents=True)
        (fail_dir / "CLAUDE.md").write_text(fail_content)


def _make_agent_config(tmp_path: Path, agent: str = "claude") -> None:
    """Create a minimal agent config.yml."""
    config_dir = tmp_path / "agents" / agent
    config_dir.mkdir(parents=True)
    (config_dir / "config.yml").write_text(
        'agent: claude\nvars:\n  instruction_files:\n    - "**/*.md"\n  main_instruction_file:\n    - "**/CLAUDE.md"\n'
    )


def _make_rule_yml(rule_dir: Path, yml_content: str) -> None:
    """Create a rule.yml file in a rule directory."""
    (rule_dir / "rule.yml").write_text(yml_content)


# ── Discovery tests ─────────────────────────────────────────────────


class TestDiscoverRules:
    """Tests for discover_rules()."""

    def test_discovers_rule_in_core(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import discover_rules

        _make_rule_dir(
            tmp_path,
            "test-rule",
            "id: CORE:S:0001\nslug: test-rule\ntitle: Test Rule\n"
            "category: structure\ntype: mechanical\nlevel: L1\nchecks: []",
        )

        rules = discover_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0].rule_id == "CORE:S:0001"
        assert rules[0].slug == "test-rule"

    def test_filter_by_rule_id(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import discover_rules

        _make_rule_dir(
            tmp_path,
            "rule-a",
            "id: CORE:S:0001\nslug: rule-a\ntitle: Rule A\n"
            "category: structure\ntype: mechanical\nlevel: L1\nchecks: []",
        )
        _make_rule_dir(
            tmp_path,
            "rule-b",
            "id: CORE:S:0002\nslug: rule-b\ntitle: Rule B\n"
            "category: structure\ntype: mechanical\nlevel: L1\nchecks: []",
        )

        rules = discover_rules(tmp_path, filter_rule="CORE:S:0002")
        assert len(rules) == 1
        assert rules[0].rule_id == "CORE:S:0002"

    def test_excludes(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import discover_rules

        _make_rule_dir(
            tmp_path,
            "excluded",
            "id: CLAUDE:S:0001\nslug: excluded\ntitle: Excluded\n"
            "category: structure\ntype: mechanical\nlevel: L1\nchecks: []",
        )

        rules = discover_rules(tmp_path, excludes=["CLAUDE:*"])
        assert len(rules) == 0

    def test_discovers_agent_rules(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import discover_rules

        agent_dir = tmp_path / "agents" / "claude" / "rules" / "test-rule"
        agent_dir.mkdir(parents=True)
        (agent_dir / "rule.md").write_text(
            "---\nid: CLAUDE:S:0001\nslug: test-rule\ntitle: Agent Rule\n"
            "category: structure\ntype: mechanical\nlevel: L1\nchecks: []\n---\n"
        )

        rules = discover_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0].rule_id == "CLAUDE:S:0001"


# ── Agent config tests ───────────────────────────────────────────────


class TestLoadAgentConfig:
    """Tests for load_agent_config()."""

    def test_loads_vars_and_excludes(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import load_agent_config

        config_dir = tmp_path / "agents" / "claude"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yml").write_text(
            'agent: claude\nvars:\n  instruction_files:\n    - "**/*.md"\nexcludes:\n  - CORE:S:0010\n'
        )

        vars_, excludes = load_agent_config(tmp_path, "claude")
        assert "instruction_files" in vars_
        assert excludes == ["CORE:S:0010"]

    def test_missing_config_returns_empty(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import load_agent_config

        vars_, excludes = load_agent_config(tmp_path, "nonexistent")
        assert vars_ == {}
        assert excludes == []


# ── Mechanical check tests ───────────────────────────────────────────


class TestMechanicalChecks:
    """Tests for mechanical check execution in harness context."""

    def test_file_exists_pass(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import HarnessStatus, run_rule

        rule_dir = _make_rule_dir(
            tmp_path,
            "file-exists",
            "id: CORE:S:0001\nslug: file-exists\ntitle: File Exists\n"
            "category: structure\ntype: mechanical\nlevel: L1\ntargets: '{{instruction_files}}'\n"
            "checks:\n- id: CORE.S.0001.file-exists\n  type: mechanical\n"
            "  severity: medium\n  name: file-exists\n  check: file_exists",
        )
        _make_fixtures(rule_dir, "# Test\n", None)  # pass fixture only

        from reporails_cli.core.harness import RuleInfo

        info = RuleInfo(
            rule_id="CORE:S:0001",
            slug="file-exists",
            title="File Exists",
            category="structure",
            rule_type="mechanical",
            level="L1",
            targets="{{instruction_files}}",
            checks=[
                {"id": "CORE.S.0001.file-exists", "type": "mechanical", "severity": "medium", "check": "file_exists"}
            ],
            rule_dir=rule_dir,
            rule_yml=rule_dir / "rule.yml",
        )

        result = run_rule(info, {"instruction_files": ["**/*.md"]})
        assert result.status == HarnessStatus.PASSED

    def test_not_implemented(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import HarnessStatus, RuleInfo, run_rule

        rule_dir = _make_rule_dir(
            tmp_path,
            "empty-checks",
            "id: CORE:S:0099\nslug: empty\ntitle: Empty\ncategory: structure\ntype: mechanical\nlevel: L1\nchecks: []",
        )

        info = RuleInfo(
            rule_id="CORE:S:0099",
            slug="empty",
            title="Empty",
            category="structure",
            rule_type="mechanical",
            level="L1",
            targets="",
            checks=[],
            rule_dir=rule_dir,
            rule_yml=rule_dir / "rule.yml",
        )

        result = run_rule(info, {})
        assert result.status == HarnessStatus.NOT_IMPLEMENTED

    def test_no_fixtures(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import HarnessStatus, RuleInfo, run_rule

        rule_dir = _make_rule_dir(
            tmp_path,
            "no-fixtures",
            "id: CORE:S:0098\nslug: no-fix\ntitle: No Fix\n"
            "category: structure\ntype: mechanical\nlevel: L1\n"
            "checks:\n- id: CORE.S.0098.check\n  type: mechanical\n  severity: medium\n  check: file_exists",
        )

        info = RuleInfo(
            rule_id="CORE:S:0098",
            slug="no-fix",
            title="No Fix",
            category="structure",
            rule_type="mechanical",
            level="L1",
            targets="",
            checks=[{"id": "CORE.S.0098.check", "type": "mechanical", "severity": "medium", "check": "file_exists"}],
            rule_dir=rule_dir,
            rule_yml=rule_dir / "rule.yml",
        )

        result = run_rule(info, {})
        assert result.status == HarnessStatus.NO_FIXTURES


# ── Deterministic check tests ────────────────────────────────────────


class TestDeterministicChecks:
    """Tests for deterministic (regex) check execution in harness context."""

    def test_pass_fixture_no_violation(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import HarnessStatus, RuleInfo, run_rule

        rule_dir = _make_rule_dir(
            tmp_path,
            "det-rule",
            "id: CORE:S:0003\nslug: det-rule\ntitle: Det Rule\n"
            "category: structure\ntype: deterministic\nlevel: L1\ntargets: '{{instruction_files}}'\n"
            "checks:\n- id: CORE.S.0003.check\n  type: deterministic\n  severity: medium\n  name: wall-of-prose",
        )
        _make_rule_yml(
            rule_dir,
            "rules:\n"
            "- id: CORE.S.0003.check\n"
            "  message: Wall of prose\n"
            "  severity: WARNING\n"
            "  languages: [generic]\n"
            "  paths:\n    include: ['**/*.md']\n"
            "  pattern-regex: '\\.\\s+[A-Z][a-z]+\\s.*\\.\\s+[A-Z][a-z]+\\s.*\\.'\n",
        )
        # Pass fixture: structured content (no wall-of-prose)
        _make_fixtures(
            rule_dir,
            "## Commands\n\n- Build: `npm run build`\n- Test: `npm test`\n",
            "This project uses npm for building. You should run npm run build. "
            "For testing use jest and run npm test. The linter is eslint.\n",
        )

        info = RuleInfo(
            rule_id="CORE:S:0003",
            slug="det-rule",
            title="Det Rule",
            category="structure",
            rule_type="deterministic",
            level="L1",
            targets="{{instruction_files}}",
            checks=[
                {"id": "CORE.S.0003.check", "type": "deterministic", "severity": "medium", "name": "wall-of-prose"}
            ],
            rule_dir=rule_dir,
            rule_yml=rule_dir / "rule.yml",
        )

        result = run_rule(info, {"instruction_files": ["**/*.md"]})
        assert result.status == HarnessStatus.PASSED

    def test_negated_deterministic(self, tmp_path: Path) -> None:
        """Negated deterministic: finding = pass, no finding = violation."""
        from reporails_cli.core.harness import HarnessStatus, RuleInfo, run_rule

        rule_dir = _make_rule_dir(
            tmp_path,
            "neg-rule",
            "id: CORE:C:0001\nslug: neg-rule\ntitle: Neg Rule\n"
            "category: content\ntype: deterministic\nlevel: L1\ntargets: '{{instruction_files}}'\n"
            "checks:\n- id: CORE.C.0001.check\n  type: deterministic\n"
            "  severity: medium\n  negate: true\n  name: has-context",
        )
        _make_rule_yml(
            rule_dir,
            "rules:\n"
            "- id: CORE.C.0001.check\n"
            "  message: Has project context\n"
            "  severity: WARNING\n"
            "  languages: [generic]\n"
            "  paths:\n    include: ['**/*.md']\n"
            "  pattern-regex: '## (Commands|Architecture)'\n",
        )
        # Pass: heading present (finding exists, negate → pass)
        # Fail: heading absent (no finding, negate → violation)
        _make_fixtures(
            rule_dir,
            "# Project\n\n## Commands\n\n- Build: `make`\n",
            "# Project\n\nSome random text without headings.\n",
        )

        info = RuleInfo(
            rule_id="CORE:C:0001",
            slug="neg-rule",
            title="Neg Rule",
            category="content",
            rule_type="deterministic",
            level="L1",
            targets="{{instruction_files}}",
            checks=[
                {
                    "id": "CORE.C.0001.check",
                    "type": "deterministic",
                    "severity": "medium",
                    "negate": True,
                    "name": "has-context",
                }
            ],
            rule_dir=rule_dir,
            rule_yml=rule_dir / "rule.yml",
        )

        result = run_rule(info, {"instruction_files": ["**/*.md"]})
        assert result.status == HarnessStatus.PASSED


# ── Semantic check tests ─────────────────────────────────────────────


class TestSemanticChecks:
    """Tests for semantic check handling (always skip)."""

    def test_semantic_always_passes(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import HarnessStatus, RuleInfo, run_rule

        rule_dir = _make_rule_dir(
            tmp_path,
            "sem-rule",
            "id: CORE:C:0005\nslug: sem-rule\ntitle: Semantic\n"
            "category: content\ntype: semantic\nlevel: L1\ntargets: '{{instruction_files}}'\n"
            "checks:\n- id: CORE.C.0005.sem\n  type: semantic\n  severity: medium\n  name: sem-eval",
        )
        _make_fixtures(rule_dir, "# Good content\n", "# Bad content\n")

        info = RuleInfo(
            rule_id="CORE:C:0005",
            slug="sem-rule",
            title="Semantic",
            category="content",
            rule_type="semantic",
            level="L1",
            targets="{{instruction_files}}",
            checks=[{"id": "CORE.C.0005.sem", "type": "semantic", "severity": "medium", "name": "sem-eval"}],
            rule_dir=rule_dir,
            rule_yml=rule_dir / "rule.yml",
        )

        result = run_rule(info, {"instruction_files": ["**/*.md"]})
        # Semantic-only rules have no M/D checks to detect violations in the
        # fail fixture, so the harness reports FAILED because the fail fixture
        # produced no violations (a harness failure — the fail case should be
        # caught but semantic-only rules can't detect it without M/D pre-checks).
        assert result.status == HarnessStatus.FAILED


# ── Batch runner tests ───────────────────────────────────────────────


class TestRunHarness:
    """Tests for run_harness() batch runner."""

    def test_runs_all_discovered_rules(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import run_harness

        _make_agent_config(tmp_path)
        rule_dir = _make_rule_dir(
            tmp_path,
            "batch-rule",
            "id: CORE:S:0001\nslug: batch-rule\ntitle: Batch Rule\n"
            "category: structure\ntype: mechanical\nlevel: L1\ntargets: '{{instruction_files}}'\n"
            "checks:\n- id: CORE.S.0001.check\n  type: mechanical\n  severity: medium\n  check: file_exists",
        )
        _make_fixtures(rule_dir, "# Test\n", None)

        results = run_harness(tmp_path)
        assert len(results) >= 1
        assert results[0].rule_id == "CORE:S:0001"


# ── git_marker tests ─────────────────────────────────────────────────


class TestGitMarker:
    """Tests for .git_marker workaround in git_tracked probe."""

    def test_git_marker_detected(self, tmp_path: Path) -> None:
        from reporails_cli.core.mechanical.checks import git_tracked

        (tmp_path / ".git_marker").touch()
        result = git_tracked(tmp_path, {}, {})
        assert result.passed

    def test_git_dir_detected(self, tmp_path: Path) -> None:
        from reporails_cli.core.mechanical.checks import git_tracked

        (tmp_path / ".git").mkdir()
        result = git_tracked(tmp_path, {}, {})
        assert result.passed

    def test_no_git_fails(self, tmp_path: Path) -> None:
        from reporails_cli.core.mechanical.checks import git_tracked

        result = git_tracked(tmp_path, {}, {})
        assert not result.passed


# ── Fixture discovery (non-.md) tests ──────────────────────────────


class TestFixtureDiscovery:
    """Tests for non-.md fixture file discovery (P1)."""

    def test_json_fixture_discovered_in_deterministic_check(self, tmp_path: Path) -> None:
        """D check should scan non-.md files (e.g. settings.json) in fixtures."""
        from reporails_cli.core.harness import HarnessStatus, RuleInfo, run_rule

        rule_dir = _make_rule_dir(
            tmp_path,
            "json-rule",
            "id: CORE:S:0099\nslug: json-rule\ntitle: JSON Rule\n"
            "category: structure\ntype: deterministic\nlevel: L1\ntargets: '{{settings_file}}'\n"
            "checks:\n- id: CORE.S.0099.check\n  type: deterministic\n  severity: medium\n  name: json-check",
        )
        _make_rule_yml(
            rule_dir,
            "rules:\n"
            "- id: CORE.S.0099.check\n"
            "  message: Bad setting\n"
            "  severity: WARNING\n"
            "  languages: [generic]\n"
            "  paths:\n    include: ['**/*.json']\n"
            "  pattern-regex: 'dangerous_setting'\n",
        )
        # Pass fixture: .json file without violation
        pass_dir = rule_dir / "tests" / "pass"
        pass_dir.mkdir(parents=True)
        (pass_dir / "settings.json").write_text('{"safe": true}')
        # Fail fixture: .json file with violation
        fail_dir = rule_dir / "tests" / "fail"
        fail_dir.mkdir(parents=True)
        (fail_dir / "settings.json").write_text('{"dangerous_setting": true}')

        info = RuleInfo(
            rule_id="CORE:S:0099",
            slug="json-rule",
            title="JSON Rule",
            category="structure",
            rule_type="deterministic",
            level="L1",
            targets="{{settings_file}}",
            checks=[{"id": "CORE.S.0099.check", "type": "deterministic", "severity": "medium"}],
            rule_dir=rule_dir,
            rule_yml=rule_dir / "rule.yml",
        )

        result = run_rule(info, {"settings_file": ".claude/settings.json"})
        assert result.status == HarnessStatus.PASSED


# ── Check name fallback tests ──────────────────────────────────────


class TestCheckNameFallback:
    """Tests for mechanical check name fallback (P4a)."""

    def test_falls_back_to_name_field(self, tmp_path: Path) -> None:
        """When 'check' key is absent, use 'name' for dispatch."""
        from reporails_cli.core.harness import _run_mechanical_check

        (tmp_path / "CLAUDE.md").write_text("# Test\n")
        result = _run_mechanical_check(
            {"name": "file_exists", "args": {"path": "**/*.md"}},
            tmp_path,
            {"instruction_files": ["**/*.md"]},
        )
        assert result.passed

    def test_check_key_takes_precedence(self, tmp_path: Path) -> None:
        """When both 'check' and 'name' are present, 'check' wins."""
        from reporails_cli.core.harness import _run_mechanical_check

        (tmp_path / "CLAUDE.md").write_text("# Test\n")
        result = _run_mechanical_check(
            {"check": "file_exists", "name": "something_else", "args": {"path": "**/*.md"}},
            tmp_path,
            {"instruction_files": ["**/*.md"]},
        )
        assert result.passed


# ── Check aliases tests ────────────────────────────────────────────


class TestCheckAliases:
    """Tests for mechanical check aliases."""

    def test_file_tracked_alias(self, tmp_path: Path) -> None:
        from reporails_cli.core.mechanical.checks import MECHANICAL_CHECKS

        assert MECHANICAL_CHECKS["file_tracked"] is MECHANICAL_CHECKS["git_tracked"]

    def test_memory_dir_exists_alias(self) -> None:
        from reporails_cli.core.mechanical.checks import MECHANICAL_CHECKS

        assert MECHANICAL_CHECKS["memory_dir_exists"] is MECHANICAL_CHECKS["directory_exists"]

    def test_total_size_check_alias(self) -> None:
        from reporails_cli.core.mechanical.checks import MECHANICAL_CHECKS

        assert MECHANICAL_CHECKS["total_size_check"] is MECHANICAL_CHECKS["aggregate_byte_size"]


# ── Multi-agent tests ──────────────────────────────────────────────


def _make_multi_agent_config(tmp_path: Path, agent: str, prefix: str, instruction_pattern: str) -> None:
    """Create an agent config with a specific prefix and instruction pattern."""
    config_dir = tmp_path / "agents" / agent
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "config.yml").write_text(
        f"agent: {agent}\nprefix: {prefix}\nvars:\n"
        f'  instruction_files:\n    - "{instruction_pattern}"\n'
        f'  main_instruction_file:\n    - "{instruction_pattern}"\n'
    )


class TestPrefixToAgentMap:
    """Tests for _build_prefix_to_agent_map()."""

    def test_builds_map_from_configs(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _build_prefix_to_agent_map

        _make_multi_agent_config(tmp_path, "claude", "CLAUDE", "**/CLAUDE.md")
        _make_multi_agent_config(tmp_path, "codex", "CODEX", "**/AGENTS.md")

        mapping = _build_prefix_to_agent_map(tmp_path)
        assert mapping == {"CLAUDE": "claude", "CODEX": "codex"}

    def test_skips_agent_without_prefix(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _build_prefix_to_agent_map

        config_dir = tmp_path / "agents" / "generic"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yml").write_text("agent: generic\nvars:\n  instruction_files:\n    - '**/*.md'\n")

        mapping = _build_prefix_to_agent_map(tmp_path)
        assert mapping == {}

    def test_empty_when_no_agents_dir(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _build_prefix_to_agent_map

        assert _build_prefix_to_agent_map(tmp_path) == {}


class TestGetRuleAgent:
    """Tests for _get_rule_agent()."""

    def test_matches_prefix(self) -> None:
        from reporails_cli.core.harness import _get_rule_agent

        prefix_map = {"CLAUDE": "claude", "CODEX": "codex"}
        assert _get_rule_agent("CLAUDE:S:0001", prefix_map) == "claude"
        assert _get_rule_agent("CODEX:S:0001", prefix_map) == "codex"

    def test_core_returns_none(self) -> None:
        from reporails_cli.core.harness import _get_rule_agent

        prefix_map = {"CLAUDE": "claude"}
        assert _get_rule_agent("CORE:S:0001", prefix_map) is None

    def test_rrails_returns_none(self) -> None:
        from reporails_cli.core.harness import _get_rule_agent

        assert _get_rule_agent("RRAILS:S:0001", {"CLAUDE": "claude"}) is None


class TestMultiAgentHarness:
    """Tests for multi-agent run_harness()."""

    def test_discovers_rules_from_multiple_agents(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import run_harness

        # Set up claude agent
        _make_multi_agent_config(tmp_path, "claude", "CLAUDE", "**/CLAUDE.md")
        claude_rule_dir = tmp_path / "agents" / "claude" / "rules" / "claude-rule"
        claude_rule_dir.mkdir(parents=True)
        (claude_rule_dir / "rule.md").write_text(
            "---\nid: CLAUDE:S:0001\nslug: claude-rule\ntitle: Claude Rule\n"
            "category: structure\ntype: mechanical\nlevel: L1\n"
            "checks:\n- id: CLAUDE.S.0001.check\n  type: mechanical\n  severity: medium\n  check: file_exists\n---\n"
        )
        pass_dir = claude_rule_dir / "tests" / "pass"
        pass_dir.mkdir(parents=True)
        (pass_dir / "CLAUDE.md").write_text("# Test\n")

        # Set up codex agent
        _make_multi_agent_config(tmp_path, "codex", "CODEX", "**/AGENTS.md")
        codex_rule_dir = tmp_path / "agents" / "codex" / "rules" / "codex-rule"
        codex_rule_dir.mkdir(parents=True)
        (codex_rule_dir / "rule.md").write_text(
            "---\nid: CODEX:S:0001\nslug: codex-rule\ntitle: Codex Rule\n"
            "category: structure\ntype: mechanical\nlevel: L1\n"
            "checks:\n- id: CODEX.S.0001.check\n  type: mechanical\n  severity: medium\n  check: file_exists\n---\n"
        )
        pass_dir = codex_rule_dir / "tests" / "pass"
        pass_dir.mkdir(parents=True)
        (pass_dir / "AGENTS.md").write_text("# Test\n")

        results = run_harness(tmp_path)
        rule_ids = {r.rule_id for r in results}
        assert "CLAUDE:S:0001" in rule_ids
        assert "CODEX:S:0001" in rule_ids


# ── Scaffold tests ─────────────────────────────────────────────────


class TestGlobToConcrete:
    """Tests for _glob_to_concrete()."""

    def test_double_star_md(self) -> None:
        from reporails_cli.core.harness import _glob_to_concrete

        assert _glob_to_concrete("**/*.md") == "scaffold.md"

    def test_nested_glob(self) -> None:
        from reporails_cli.core.harness import _glob_to_concrete

        assert _glob_to_concrete(".claude/rules/**/*.md") == ".claude/rules/scaffold.md"

    def test_plain_path_preserved(self) -> None:
        from reporails_cli.core.harness import _glob_to_concrete

        assert _glob_to_concrete(".claude/settings.json") == ".claude/settings.json"


class TestScaffoldFixture:
    """Tests for _scaffold_fixture()."""

    def test_scaffolds_file_for_file_exists(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _scaffold_fixture

        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()
        (fixture_dir / "CLAUDE.md").write_text("# Existing\n")

        checks = [{"type": "mechanical", "check": "file_exists", "args": {"path": "{{skills_dir}}/**/*.md"}}]
        result = _scaffold_fixture(fixture_dir, checks, {"skills_dir": ".claude/skills"})

        assert result is not None
        assert (result / ".claude" / "skills" / "scaffold.md").exists()
        # Original content preserved
        assert (result / "CLAUDE.md").read_text() == "# Existing\n"
        # Cleanup
        import shutil

        shutil.rmtree(result)

    def test_scaffolds_git_marker(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _scaffold_fixture

        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [{"type": "mechanical", "check": "git_tracked"}]
        result = _scaffold_fixture(fixture_dir, checks, {})

        assert result is not None
        assert (result / ".git_marker").exists()
        import shutil

        shutil.rmtree(result)

    def test_scaffolds_directory(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _scaffold_fixture

        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [{"type": "mechanical", "check": "directory_exists", "args": {"path": "{{memory_dir}}"}}]
        result = _scaffold_fixture(fixture_dir, checks, {"memory_dir": ".claude/memory"})

        assert result is not None
        assert (result / ".claude" / "memory").is_dir()
        import shutil

        shutil.rmtree(result)

    def test_no_scaffold_for_deterministic_only(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _scaffold_fixture

        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [{"type": "deterministic", "id": "test", "severity": "medium"}]
        result = _scaffold_fixture(fixture_dir, checks, {})
        assert result is None

    def test_no_scaffold_for_semantic_only(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _scaffold_fixture

        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [{"type": "semantic", "id": "test"}]
        result = _scaffold_fixture(fixture_dir, checks, {})
        assert result is None

    def test_scaffolds_file_removal_for_file_absent(self, tmp_path: Path) -> None:
        """Pass scaffold removes the forbidden file for file_absent checks."""
        from reporails_cli.core.harness import _scaffold_fixture

        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()
        (fixture_dir / "README.md").write_text("# README")

        checks = [{"type": "mechanical", "check": "file_absent", "args": {"pattern": "README.md"}}]
        result = _scaffold_fixture(fixture_dir, checks, {})

        assert result is not None
        assert not (result / "README.md").exists()
        import shutil

        shutil.rmtree(result)


# ── Fail scaffold tests ─────────────────────────────────────────────


class TestScaffoldFailFixture:
    """Tests for _scaffold_fail_fixture()."""

    def test_filename_mismatch_renames_file(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _scaffold_fail_fixture

        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()
        (fixture_dir / "CLAUDE.md").write_text("# Test")

        checks = [
            {
                "type": "mechanical",
                "check": "filename_matches_pattern",
                "args": {"pattern": r"(?i)^(CLAUDE|AGENTS)\.md$", "path": "**/*.md"},
            }
        ]
        result = _scaffold_fail_fixture(fixture_dir, checks, {"instruction_files": ["**/*.md"]})

        assert result is not None
        # Original file should be renamed to invalid name (preserving extension)
        assert (result / "_scaffold_invalid.md").exists()
        import shutil

        shutil.rmtree(result)

    def test_glob_count_deficit_reduces_files(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _scaffold_fail_fixture

        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()
        (fixture_dir / "a.md").write_text("a")
        (fixture_dir / "b.md").write_text("b")

        checks = [{"type": "mechanical", "check": "glob_count", "args": {"pattern": "**/*.md", "min": 2}}]
        result = _scaffold_fail_fixture(fixture_dir, checks, {})

        assert result is not None
        md_files = list(result.glob("**/*.md"))
        assert len(md_files) < 2
        import shutil

        shutil.rmtree(result)

    def test_file_present_creates_forbidden_file(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _scaffold_fail_fixture

        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [{"type": "mechanical", "check": "file_absent", "args": {"pattern": "README.md"}}]
        result = _scaffold_fail_fixture(fixture_dir, checks, {})

        assert result is not None
        assert (result / "README.md").exists()
        import shutil

        shutil.rmtree(result)

    def test_no_scaffold_for_unsupported_checks(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import _scaffold_fail_fixture

        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [{"type": "mechanical", "check": "file_exists", "args": {"path": "**/*.md"}}]
        result = _scaffold_fail_fixture(fixture_dir, checks, {})
        assert result is None


class TestFailScaffoldIntegration:
    """End-to-end: rules with structural M checks pass via scaffolding."""

    def test_filename_matches_pattern_with_scaffold(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import HarnessStatus, RuleInfo, run_rule

        rule_dir = _make_rule_dir(
            tmp_path,
            "fname-rule",
            "id: CORE:S:0004\nslug: fname-rule\ntitle: Filename Rule\n"
            "category: structure\ntype: mechanical\nlevel: L1\ntargets: '{{instruction_files}}'\n"
            "checks:\n- id: CORE.S.0004.fname\n  type: mechanical\n  severity: medium\n"
            "  check: filename_matches_pattern\n  args:\n    pattern: '(?i)^(CLAUDE|AGENTS)\\.md$'",
        )
        # Pass fixture: properly named file
        pass_dir = rule_dir / "tests" / "pass"
        pass_dir.mkdir(parents=True)
        (pass_dir / "CLAUDE.md").write_text("# Good\n")
        # Fail fixture: empty — scaffold will create invalid name
        fail_dir = rule_dir / "tests" / "fail"
        fail_dir.mkdir(parents=True)
        (fail_dir / "CLAUDE.md").write_text("# Will be renamed\n")

        info = RuleInfo(
            rule_id="CORE:S:0004",
            slug="fname-rule",
            title="Filename Rule",
            category="structure",
            rule_type="mechanical",
            level="L1",
            targets="{{instruction_files}}",
            checks=[
                {
                    "id": "CORE.S.0004.fname",
                    "type": "mechanical",
                    "severity": "medium",
                    "check": "filename_matches_pattern",
                    "args": {"pattern": r"(?i)^(CLAUDE|AGENTS)\.md$", "path": "**/*.md"},
                }
            ],
            rule_dir=rule_dir,
            rule_yml=rule_dir / "rule.yml",
        )

        result = run_rule(info, {"instruction_files": ["**/*.md"]})
        assert result.status == HarnessStatus.PASSED

    def test_file_absent_with_scaffold(self, tmp_path: Path) -> None:
        from reporails_cli.core.harness import HarnessStatus, RuleInfo, run_rule

        rule_dir = _make_rule_dir(
            tmp_path,
            "absent-rule",
            "id: CORE:S:0005\nslug: absent-rule\ntitle: Absent Rule\n"
            "category: structure\ntype: mechanical\nlevel: L1\n"
            "checks:\n- id: CORE.S.0005.absent\n  type: mechanical\n  severity: medium\n"
            "  check: file_absent\n  args:\n    pattern: README.md",
        )
        # Pass fixture: no README.md
        pass_dir = rule_dir / "tests" / "pass"
        pass_dir.mkdir(parents=True)
        (pass_dir / "CLAUDE.md").write_text("# Good\n")
        # Fail fixture: empty — scaffold will create README.md
        fail_dir = rule_dir / "tests" / "fail"
        fail_dir.mkdir(parents=True)
        (fail_dir / "CLAUDE.md").write_text("# Test\n")

        info = RuleInfo(
            rule_id="CORE:S:0005",
            slug="absent-rule",
            title="Absent Rule",
            category="structure",
            rule_type="mechanical",
            level="L1",
            targets="",
            checks=[
                {
                    "id": "CORE.S.0005.absent",
                    "type": "mechanical",
                    "severity": "medium",
                    "check": "file_absent",
                    "args": {"pattern": "README.md"},
                }
            ],
            rule_dir=rule_dir,
            rule_yml=rule_dir / "rule.yml",
        )

        result = run_rule(info, {})
        assert result.status == HarnessStatus.PASSED
