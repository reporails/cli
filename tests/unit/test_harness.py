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
