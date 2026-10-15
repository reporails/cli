"""Unit tests for project config loading, package paths, and multi-source rule loading."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from reporails_cli.core.platform.config.bootstrap import get_package_paths
from reporails_cli.core.platform.config.config import get_project_config


class TestGetProjectConfig:
    """Test get_project_config loading from .ails/config.yml."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_returns_defaults_when_missing(self, tmp_path: Path) -> None:
        config = get_project_config(tmp_path)
        assert config.packages == []
        assert config.disabled_rules == []

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_loads_all_fields(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("packages:\n  - custom\ndisabled_rules:\n  - S1\n")
        config = get_project_config(tmp_path)
        assert config.packages == ["custom"]
        assert config.disabled_rules == ["S1"]

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_segmentation_defaults_to_legacy(self, tmp_path: Path) -> None:
        assert get_project_config(tmp_path).mapper.segmentation == "legacy"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_segmentation_structure_aware_parsed(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("segmentation: structure-aware\n")
        assert get_project_config(tmp_path).mapper.segmentation == "structure-aware"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_segmentation_unknown_value_falls_back_to_legacy(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("segmentation: bogus-mode\n")
        assert get_project_config(tmp_path).mapper.segmentation == "legacy"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_malformed_yaml_is_refused(self, tmp_path: Path, make_config_file) -> None:
        from reporails_cli.core.platform.contract.errors import ConfigUnreadableError

        make_config_file(": : :\n  bad yaml [[[")
        with pytest.raises(ConfigUnreadableError):
            get_project_config(tmp_path)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_returns_defaults_on_empty_file(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("")
        config = get_project_config(tmp_path)
        assert config.packages == []


class TestGlobalDefaultsMerged:
    """Test that get_project_config() falls back to global config for unset values."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_inherits_global_default_agent(self, tmp_path: Path, make_config_file) -> None:
        """Project without default_agent inherits global value."""
        from reporails_cli.core.platform.dto.results import GlobalConfig

        make_config_file("packages:\n  - custom\n")
        with patch(
            "reporails_cli.core.platform.config.config.get_global_config",
            return_value=GlobalConfig(default_agent="claude"),
        ):
            config = get_project_config(tmp_path)
        assert config.default_agent == "claude"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_project_overrides_global_default_agent(self, tmp_path: Path, make_config_file) -> None:
        """Project default_agent wins over global."""
        from reporails_cli.core.platform.dto.results import GlobalConfig

        make_config_file("default_agent: cursor\n")
        with patch(
            "reporails_cli.core.platform.config.config.get_global_config",
            return_value=GlobalConfig(default_agent="claude"),
        ):
            config = get_project_config(tmp_path)
        assert config.default_agent == "cursor"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_config_file_inherits_global(self, tmp_path: Path) -> None:
        """No .ails/config.yml — global defaults apply."""
        from reporails_cli.core.platform.dto.results import GlobalConfig

        with patch(
            "reporails_cli.core.platform.config.config.get_global_config",
            return_value=GlobalConfig(default_agent="claude"),
        ):
            config = get_project_config(tmp_path)
        assert config.default_agent == "claude"


class TestGetPackagePaths:
    """Test get_package_paths resolution."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_returns_existing_dirs(self, tmp_path: Path) -> None:
        pkg_dir = tmp_path / ".ails" / "packages" / "recommended"
        pkg_dir.mkdir(parents=True)
        paths = get_package_paths(tmp_path, ["recommended"])
        assert paths == [pkg_dir]

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_missing_dir_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from reporails_cli.core.platform.contract.errors import ConfigUnreadableError

        monkeypatch.setattr(
            "reporails_cli.core.platform.config.bootstrap.get_global_packages_path",
            lambda: tmp_path / "home" / "packages",
        )
        (tmp_path / ".ails" / "packages").mkdir(parents=True)
        with pytest.raises(ConfigUnreadableError, match="nonexistent"):
            get_package_paths(tmp_path, ["nonexistent"])

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_missing_package_after_existing_one_still_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reporails_cli.core.platform.contract.errors import ConfigUnreadableError

        monkeypatch.setattr(
            "reporails_cli.core.platform.config.bootstrap.get_global_packages_path",
            lambda: tmp_path / "home" / "packages",
        )
        pkg_base = tmp_path / ".ails" / "packages"
        (pkg_base / "exists").mkdir(parents=True)
        with pytest.raises(ConfigUnreadableError, match="missing"):
            get_package_paths(tmp_path, ["exists", "missing"])

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_empty_packages_list(self, tmp_path: Path) -> None:
        paths = get_package_paths(tmp_path, [])
        assert paths == []

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_resolves_from_global_packages(self, tmp_path: Path) -> None:
        """Global ~/.reporails/packages/ is checked as fallback."""
        global_pkg = tmp_path / "global_home" / "packages" / "recommended"
        global_pkg.mkdir(parents=True)

        project = tmp_path / "project"
        project.mkdir()

        with patch(
            "reporails_cli.core.platform.config.bootstrap.get_global_packages_path",
            return_value=tmp_path / "global_home" / "packages",
        ):
            paths = get_package_paths(project, ["recommended"])
        assert paths == [global_pkg]

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_project_local_overrides_global(self, tmp_path: Path) -> None:
        """Project-local package takes priority over global."""
        global_pkg = tmp_path / "global_home" / "packages" / "recommended"
        global_pkg.mkdir(parents=True)

        project = tmp_path / "project"
        local_pkg = project / ".ails" / "packages" / "recommended"
        local_pkg.mkdir(parents=True)

        with patch(
            "reporails_cli.core.platform.config.bootstrap.get_global_packages_path",
            return_value=tmp_path / "global_home" / "packages",
        ):
            paths = get_package_paths(project, ["recommended"])
        assert paths == [local_pkg]

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_mixed_local_and_global(self, tmp_path: Path) -> None:
        """One package local, another global."""
        global_pkg = tmp_path / "global_home" / "packages" / "recommended"
        global_pkg.mkdir(parents=True)

        project = tmp_path / "project"
        local_pkg = project / ".ails" / "packages" / "custom"
        local_pkg.mkdir(parents=True)

        with patch(
            "reporails_cli.core.platform.config.bootstrap.get_global_packages_path",
            return_value=tmp_path / "global_home" / "packages",
        ):
            paths = get_package_paths(project, ["custom", "recommended"])
        assert len(paths) == 2
        assert paths[0] == local_pkg
        assert paths[1] == global_pkg


# Helper to create a minimal rule.md file with frontmatter (new coordinate format)
RULE_MD_TEMPLATE = """\
---
id: "{rule_id}"
title: {title}
category: structure
type: deterministic
level: L2
slug: {slug}
targets: '{{{{instruction_files}}}}'
backed_by:
  - anthropic-docs
---

# {title}

Test rule content.
"""


def _create_rule(directory: Path, rule_id: str, title: str) -> None:
    """Create a minimal rule.md file in a slug directory."""
    slug = title.lower().replace(" ", "-")
    rule_dir = directory / slug
    rule_dir.mkdir(parents=True, exist_ok=True)
    (rule_dir / "rule.md").write_text(RULE_MD_TEMPLATE.format(rule_id=rule_id, title=title, slug=slug))


class TestLoadRulesWithPackages:
    """Test load_rules with project packages and disabled rules."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_additional_path_overrides_framework(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        # Create framework rules dir
        rules_dir = tmp_path / "rules"
        core_dir = rules_dir / "core" / "structure"
        _create_rule(core_dir, "CORE:S:0001", "Framework S1")

        # Create custom package with rule that overrides CORE:S:0001
        pkg_dir = tmp_path / "custom"
        _create_rule(pkg_dir, "CORE:S:0001", "Custom S1")

        # Also need sources.yml for tier derivation
        docs_dir = rules_dir / "docs"
        docs_dir.mkdir(parents=True)
        (docs_dir / "sources.yml").write_text("general:\n  - id: anthropic-docs\n    weight: 1.0\n")

        # Additional paths override primary framework rules
        rules = load_rules(
            rules_paths=[rules_dir, pkg_dir],
        )
        assert "CORE:S:0001" in rules
        assert rules["CORE:S:0001"].title == "Custom S1"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_disabled_rules_excluded(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        # Create framework rules
        rules_dir = tmp_path / "rules"
        core_dir = rules_dir / "core" / "structure"
        _create_rule(core_dir, "CORE:S:0001", "Size Limits")
        _create_rule(core_dir, "CORE:S:0002", "Other Rule")

        # Sources for tier
        docs_dir = rules_dir / "docs"
        docs_dir.mkdir(parents=True)
        (docs_dir / "sources.yml").write_text("general:\n  - id: anthropic-docs\n    weight: 1.0\n")

        # Project config disabling CORE:S:0001
        project = tmp_path / "project"
        config_dir = project / ".ails"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yml").write_text('disabled_rules:\n  - "CORE:S:0001"\n')

        rules = load_rules(
            rules_paths=[rules_dir],
            project_root=project,
        )
        assert "CORE:S:0001" not in rules
        assert "CORE:S:0002" in rules

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_disabled_nonexistent_rule_harmless(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        rules_dir = tmp_path / "rules"
        core_dir = rules_dir / "core" / "structure"
        _create_rule(core_dir, "CORE:S:0001", "Size Limits")

        docs_dir = rules_dir / "docs"
        docs_dir.mkdir(parents=True)
        (docs_dir / "sources.yml").write_text("general:\n  - id: anthropic-docs\n    weight: 1.0\n")

        project = tmp_path / "project"
        config_dir = project / ".ails"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yml").write_text("disabled_rules:\n  - NOPE\n")

        rules = load_rules(
            rules_paths=[rules_dir],
            project_root=project,
        )
        assert "CORE:S:0001" in rules

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_project_root_backward_compat(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        rules_dir = tmp_path / "rules"
        core_dir = rules_dir / "core" / "structure"
        _create_rule(core_dir, "CORE:S:0001", "Size Limits")

        docs_dir = rules_dir / "docs"
        docs_dir.mkdir(parents=True)
        (docs_dir / "sources.yml").write_text("general:\n  - id: anthropic-docs\n    weight: 1.0\n")

        # No project_root — backward compatible
        rules = load_rules(rules_paths=[rules_dir])
        assert "CORE:S:0001" in rules


class TestLoadRulesRulePackages:
    """`packages:` in a config loads that package's rules after the bundled ones."""

    @staticmethod
    def _framework(tmp_path: Path) -> Path:
        rules_dir = tmp_path / "rules"
        _create_rule(rules_dir / "core" / "structure", "CORE:S:0001", "Bundled S1")
        docs_dir = rules_dir / "docs"
        docs_dir.mkdir(parents=True)
        (docs_dir / "sources.yml").write_text("general:\n  - id: anthropic-docs\n    weight: 1.0\n")
        return rules_dir

    @staticmethod
    def _project(tmp_path: Path, config: str) -> Path:
        project = tmp_path / "project"
        (project / ".ails").mkdir(parents=True)
        (project / ".ails" / "config.yml").write_text(config)
        return project

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_listed_package_rule_is_loaded(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        rules_dir = self._framework(tmp_path)
        project = self._project(tmp_path, "packages:\n  - mypack\n")
        _create_rule(project / ".ails" / "packages" / "mypack", "CORE:S:0900", "Pack Rule")

        rules = load_rules(rules_paths=[rules_dir], project_root=project)
        assert rules["CORE:S:0900"].title == "Pack Rule"
        assert rules["CORE:S:0001"].title == "Bundled S1"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_unlisted_package_rule_is_not_loaded(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        rules_dir = self._framework(tmp_path)
        project = self._project(tmp_path, "disabled_rules: []\n")
        _create_rule(project / ".ails" / "packages" / "mypack", "CORE:S:0900", "Pack Rule")

        rules = load_rules(rules_paths=[rules_dir], project_root=project)
        assert "CORE:S:0900" not in rules

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_package_rule_with_a_bundled_id_stops_the_run_naming_both(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules
        from reporails_cli.core.platform.contract.errors import ConfigUnreadableError

        rules_dir = self._framework(tmp_path)
        project = self._project(tmp_path, "packages:\n  - mypack\n")
        _create_rule(project / ".ails" / "packages" / "mypack", "CORE:S:0001", "Pack Replacement")

        with pytest.raises(ConfigUnreadableError) as excinfo:
            load_rules(rules_paths=[rules_dir], project_root=project)

        message = str(excinfo.value)
        assert "'mypack'" in message
        assert "CORE:S:0001" in message
        assert "own ID prefix" in message

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_two_packages_defining_the_same_id_stop_the_run_naming_both(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules
        from reporails_cli.core.platform.contract.errors import ConfigUnreadableError

        rules_dir = self._framework(tmp_path)
        project = self._project(tmp_path, "packages:\n  - packa\n  - packb\n")
        _create_rule(project / ".ails" / "packages" / "packa", "PACK:S:0001", "A")
        _create_rule(project / ".ails" / "packages" / "packb", "PACK:S:0001", "B")

        with pytest.raises(ConfigUnreadableError) as excinfo:
            load_rules(rules_paths=[rules_dir], project_root=project)

        message = str(excinfo.value)
        assert "'packa'" in message
        assert "'packb'" in message
        assert "PACK:S:0001" in message

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_package_rule_with_its_own_prefix_loads_beside_the_bundled_rules(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        rules_dir = self._framework(tmp_path)
        project = self._project(tmp_path, "packages:\n  - mypack\n")
        _create_rule(project / ".ails" / "packages" / "mypack", "MYPACK:S:0001", "Own Prefix")

        rules = load_rules(rules_paths=[rules_dir], project_root=project)
        assert rules["MYPACK:S:0001"].title == "Own Prefix"
        assert rules["CORE:S:0001"].title == "Bundled S1"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_global_package_is_the_fallback_and_project_copy_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        global_packages = tmp_path / "home" / "packages"
        monkeypatch.setattr(
            "reporails_cli.core.platform.config.bootstrap.get_global_packages_path",
            lambda: global_packages,
        )
        rules_dir = self._framework(tmp_path)
        _create_rule(global_packages / "globalpack", "CORE:S:0901", "Global Rule")
        _create_rule(global_packages / "both", "CORE:S:0902", "Global Both")

        project = self._project(tmp_path, "packages:\n  - globalpack\n  - both\n")
        _create_rule(project / ".ails" / "packages" / "both", "CORE:S:0903", "Project Both")

        rules = load_rules(rules_paths=[rules_dir], project_root=project)
        assert rules["CORE:S:0901"].title == "Global Rule"
        assert rules["CORE:S:0903"].title == "Project Both"
        assert "CORE:S:0902" not in rules

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_disabled_rules_turns_a_package_rule_off(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        rules_dir = self._framework(tmp_path)
        project = self._project(tmp_path, 'packages:\n  - mypack\ndisabled_rules:\n  - "CORE:S:0900"\n')
        _create_rule(project / ".ails" / "packages" / "mypack", "CORE:S:0900", "Pack Rule")

        rules = load_rules(rules_paths=[rules_dir], project_root=project)
        assert "CORE:S:0900" not in rules
        assert "CORE:S:0001" in rules

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_scan_root_packages_resolve_against_scan_root(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        rules_dir = self._framework(tmp_path)
        project = self._project(tmp_path, "disabled_rules: []\n")
        scan = tmp_path / "scan"
        (scan / ".ails").mkdir(parents=True)
        (scan / ".ails" / "config.yml").write_text("packages:\n  - scanpack\n")
        _create_rule(scan / ".ails" / "packages" / "scanpack", "CORE:S:0904", "Scan Rule")

        rules = load_rules(rules_paths=[rules_dir], project_root=project, scan_root=scan)
        assert rules["CORE:S:0904"].title == "Scan Rule"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_missing_package_raises_naming_it_and_both_folders(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules
        from reporails_cli.core.platform.contract.errors import ConfigUnreadableError

        global_packages = tmp_path / "home" / "packages"
        monkeypatch.setattr(
            "reporails_cli.core.platform.config.bootstrap.get_global_packages_path",
            lambda: global_packages,
        )
        rules_dir = self._framework(tmp_path)
        project = self._project(tmp_path, "packages:\n  - ghostpack\n")

        with pytest.raises(ConfigUnreadableError) as excinfo:
            load_rules(rules_paths=[rules_dir], project_root=project)

        message = str(excinfo.value)
        assert "ghostpack" in message
        assert str(project / ".ails" / "packages" / "ghostpack") in message
        assert str(global_packages / "ghostpack") in message


class TestPackageRuleBehaviour:
    """A package rule is a first-class rule: own ID prefix, fresh reads, `depends_on` honoured."""

    @staticmethod
    def _project(tmp_path: Path) -> Path:
        project = tmp_path / "project"
        (project / ".ails").mkdir(parents=True)
        (project / ".ails" / "config.yml").write_text("packages:\n  - mypack\n")
        return project

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_a_package_rule_keeps_its_own_id_prefix(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        project = self._project(tmp_path)
        _create_rule(project / ".ails" / "packages" / "mypack", "MYPACK:S:0001", "Own Prefix")
        rules = load_rules(project_root=project, agent="claude")
        assert "MYPACK:S:0001" in rules
        assert not any(rid.startswith(("CODEX:", "COPILOT:", "CURSOR:")) for rid in rules)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_another_known_agents_package_rule_is_dropped(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        project = self._project(tmp_path)
        _create_rule(project / ".ails" / "packages" / "mypack", "CODEX:S:0999", "Codex Pack")
        assert "CODEX:S:0999" not in load_rules(project_root=project, agent="claude")
        assert "CODEX:S:0999" in load_rules(project_root=project, agent="codex")

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_an_edited_package_rule_is_read_fresh(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        project = self._project(tmp_path)
        pack = project / ".ails" / "packages" / "mypack"
        _create_rule(pack, "MYPACK:S:0001", "Old Title")
        assert load_rules(project_root=project)["MYPACK:S:0001"].title == "Old Title"
        (pack / "old-title" / "rule.md").write_text(
            RULE_MD_TEMPLATE.format(rule_id="MYPACK:S:0001", title="New Title", slug="old-title")
        )
        assert load_rules(project_root=project)["MYPACK:S:0001"].title == "New Title"

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_run_dependencies_include_package_rules(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules, rule_dependencies

        project = self._project(tmp_path)
        pack = project / ".ails" / "packages" / "mypack" / "dependent"
        pack.mkdir(parents=True)
        (pack / "rule.md").write_text(
            RULE_MD_TEMPLATE.format(rule_id="CORE:S:0952", title="Dependent", slug="dependent").replace(
                "---\n\n#", "depends_on: [CORE:C:0037]\n---\n\n#", 1
            )
        )
        deps = rule_dependencies(load_rules(project_root=project, scan_root=project, agent="claude"))
        assert deps["CORE:S:0952"] == frozenset({"CORE:C:0037"})

        from reporails_cli.core.platform.dto.models import LocalFinding
        from reporails_cli.core.platform.policy.dependencies import drop_dependent_findings

        found = [
            LocalFinding("CLAUDE.md", 1, "warning", "CORE:S:0952", "m"),
            LocalFinding("CLAUDE.md", 2, "warning", "CORE:C:0037", "m"),
        ]
        assert [f.rule for f in drop_dependent_findings(found, deps, frozenset())] == ["CORE:C:0037"]


class TestExplainIgnoresProjectDisabledRules:
    """`explain` describes a rule even when the project disables it: disabling stops processing, not lookup."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_cli_explain_shows_disabled_rule(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from reporails_cli.interfaces.cli.main import app

        project = tmp_path / "project"
        (project / ".ails").mkdir(parents=True)
        (project / ".ails" / "config.yml").write_text("disabled_rules:\n  - CORE:C:0037\n")
        monkeypatch.chdir(project)

        result = CliRunner().invoke(app, ["explain", "CORE:C:0037"])

        assert result.exit_code == 0
        assert "CORE:C:0037" in result.stdout

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_mcp_explain_shows_disabled_rule(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from reporails_cli.interfaces.mcp.rule_tools import explain_tool

        project = tmp_path / "project"
        (project / ".ails").mkdir(parents=True)
        (project / ".ails" / "config.yml").write_text("disabled_rules:\n  - CORE:C:0037\n")
        monkeypatch.chdir(project)

        result = explain_tool("CORE:C:0037")

        assert not (isinstance(result, dict) and "error" in result)
        assert "CORE:C:0037" in str(result)
