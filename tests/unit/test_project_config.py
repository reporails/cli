"""Unit tests for project config loading, package paths, and multi-source rule loading."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from reporails_cli.core.bootstrap import get_package_paths, get_project_config


class TestGetProjectConfig:
    """Test get_project_config loading from .reporails/config.yml."""

    def test_returns_defaults_when_missing(self, tmp_path: Path) -> None:
        config = get_project_config(tmp_path)
        assert config.packages == []
        assert config.disabled_rules == []
        assert config.framework_version is None
        assert config.experimental is False
        assert config.recommended is True

    def test_loads_packages(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("packages:\n  - recommended\n  - custom\n")
        config = get_project_config(tmp_path)
        assert config.packages == ["recommended", "custom"]

    def test_loads_disabled_rules(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("disabled_rules:\n  - S1\n  - C7\n")
        config = get_project_config(tmp_path)
        assert config.disabled_rules == ["S1", "C7"]

    def test_loads_all_fields(self, tmp_path: Path, make_config_file) -> None:
        make_config_file(
            "framework_version: '0.1.0'\npackages:\n  - recommended\ndisabled_rules:\n  - S1\nexperimental: true\n"
        )
        config = get_project_config(tmp_path)
        assert config.framework_version == "0.1.0"
        assert config.packages == ["recommended"]
        assert config.disabled_rules == ["S1"]
        assert config.experimental is True

    def test_recommended_true_by_default(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("packages:\n  - custom\n")
        config = get_project_config(tmp_path)
        assert config.recommended is True

    def test_recommended_opt_out(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("recommended: false\n")
        config = get_project_config(tmp_path)
        assert config.recommended is False

    def test_returns_defaults_on_malformed_yaml(self, tmp_path: Path, make_config_file) -> None:
        make_config_file(": : :\n  bad yaml [[[")
        config = get_project_config(tmp_path)
        assert config.packages == []
        assert config.disabled_rules == []

    def test_malformed_yaml_inherits_global(self, tmp_path: Path, make_config_file) -> None:
        from reporails_cli.core.models import GlobalConfig

        make_config_file(": : :\n  bad yaml [[[")
        with patch(
            "reporails_cli.core.bootstrap.get_global_config",
            return_value=GlobalConfig(default_agent="claude", recommended=False),
        ):
            config = get_project_config(tmp_path)
        assert config.default_agent == "claude"
        assert config.recommended is False

    def test_returns_defaults_on_empty_file(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("")
        config = get_project_config(tmp_path)
        assert config.packages == []

    def test_loads_exclude_dirs(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("exclude_dirs:\n  - tests\n  - vendor\n")
        config = get_project_config(tmp_path)
        assert config.exclude_dirs == ["tests", "vendor"]

    def test_exclude_dirs_defaults_empty(self, tmp_path: Path, make_config_file) -> None:
        make_config_file("packages:\n  - custom\n")
        config = get_project_config(tmp_path)
        assert config.exclude_dirs == []


class TestGlobalDefaultsMerged:
    """Test that get_project_config() falls back to global config for unset values."""

    def test_inherits_global_default_agent(self, tmp_path: Path, make_config_file) -> None:
        """Project without default_agent inherits global value."""
        from reporails_cli.core.models import GlobalConfig

        make_config_file("packages:\n  - custom\n")
        with patch(
            "reporails_cli.core.bootstrap.get_global_config",
            return_value=GlobalConfig(default_agent="claude"),
        ):
            config = get_project_config(tmp_path)
        assert config.default_agent == "claude"

    def test_project_overrides_global_default_agent(self, tmp_path: Path, make_config_file) -> None:
        """Project default_agent wins over global."""
        from reporails_cli.core.models import GlobalConfig

        make_config_file("default_agent: cursor\n")
        with patch(
            "reporails_cli.core.bootstrap.get_global_config",
            return_value=GlobalConfig(default_agent="claude"),
        ):
            config = get_project_config(tmp_path)
        assert config.default_agent == "cursor"

    def test_inherits_global_recommended(self, tmp_path: Path, make_config_file) -> None:
        """Project without recommended key inherits global value."""
        from reporails_cli.core.models import GlobalConfig

        make_config_file("packages:\n  - custom\n")
        with patch(
            "reporails_cli.core.bootstrap.get_global_config",
            return_value=GlobalConfig(recommended=False),
        ):
            config = get_project_config(tmp_path)
        assert config.recommended is False

    def test_project_overrides_global_recommended(self, tmp_path: Path, make_config_file) -> None:
        """Project explicit recommended: false wins over global true."""
        from reporails_cli.core.models import GlobalConfig

        make_config_file("recommended: false\n")
        with patch(
            "reporails_cli.core.bootstrap.get_global_config",
            return_value=GlobalConfig(recommended=True),
        ):
            config = get_project_config(tmp_path)
        assert config.recommended is False

    def test_no_config_file_inherits_global(self, tmp_path: Path) -> None:
        """No .reporails/config.yml — global defaults apply."""
        from reporails_cli.core.models import GlobalConfig

        with patch(
            "reporails_cli.core.bootstrap.get_global_config",
            return_value=GlobalConfig(default_agent="claude", recommended=False),
        ):
            config = get_project_config(tmp_path)
        assert config.default_agent == "claude"
        assert config.recommended is False


class TestGetPackagePaths:
    """Test get_package_paths resolution."""

    def test_returns_existing_dirs(self, tmp_path: Path) -> None:
        pkg_dir = tmp_path / ".reporails" / "packages" / "recommended"
        pkg_dir.mkdir(parents=True)
        paths = get_package_paths(tmp_path, ["recommended"])
        assert paths == [pkg_dir]

    def test_skips_missing_dirs(self, tmp_path: Path) -> None:
        (tmp_path / ".reporails" / "packages").mkdir(parents=True)
        paths = get_package_paths(tmp_path, ["nonexistent"])
        assert paths == []

    def test_mixed_existing_and_missing(self, tmp_path: Path) -> None:
        pkg_base = tmp_path / ".reporails" / "packages"
        (pkg_base / "exists").mkdir(parents=True)
        paths = get_package_paths(tmp_path, ["exists", "missing"])
        assert len(paths) == 1
        assert paths[0].name == "exists"

    def test_empty_packages_list(self, tmp_path: Path) -> None:
        paths = get_package_paths(tmp_path, [])
        assert paths == []

    def test_resolves_from_global_packages(self, tmp_path: Path) -> None:
        """Global ~/.reporails/packages/ is checked as fallback."""
        global_pkg = tmp_path / "global_home" / "packages" / "recommended"
        global_pkg.mkdir(parents=True)

        project = tmp_path / "project"
        project.mkdir()

        with patch(
            "reporails_cli.core.bootstrap.get_global_packages_path",
            return_value=tmp_path / "global_home" / "packages",
        ):
            paths = get_package_paths(project, ["recommended"])
        assert paths == [global_pkg]

    def test_project_local_overrides_global(self, tmp_path: Path) -> None:
        """Project-local package takes priority over global."""
        global_pkg = tmp_path / "global_home" / "packages" / "recommended"
        global_pkg.mkdir(parents=True)

        project = tmp_path / "project"
        local_pkg = project / ".reporails" / "packages" / "recommended"
        local_pkg.mkdir(parents=True)

        with patch(
            "reporails_cli.core.bootstrap.get_global_packages_path",
            return_value=tmp_path / "global_home" / "packages",
        ):
            paths = get_package_paths(project, ["recommended"])
        assert paths == [local_pkg]

    def test_mixed_local_and_global(self, tmp_path: Path) -> None:
        """One package local, another global."""
        global_pkg = tmp_path / "global_home" / "packages" / "recommended"
        global_pkg.mkdir(parents=True)

        project = tmp_path / "project"
        local_pkg = project / ".reporails" / "packages" / "custom"
        local_pkg.mkdir(parents=True)

        with patch(
            "reporails_cli.core.bootstrap.get_global_packages_path",
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

    def test_additional_path_overrides_framework(self, tmp_path: Path) -> None:
        from reporails_cli.core.registry import load_rules

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
            include_experimental=True,
        )
        assert "CORE:S:0001" in rules
        assert rules["CORE:S:0001"].title == "Custom S1"

    def test_disabled_rules_excluded(self, tmp_path: Path) -> None:
        from reporails_cli.core.registry import load_rules

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
        config_dir = project / ".reporails"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yml").write_text('disabled_rules:\n  - "CORE:S:0001"\n')

        rules = load_rules(
            rules_paths=[rules_dir],
            include_experimental=True,
            project_root=project,
        )
        assert "CORE:S:0001" not in rules
        assert "CORE:S:0002" in rules

    def test_disabled_nonexistent_rule_harmless(self, tmp_path: Path) -> None:
        from reporails_cli.core.registry import load_rules

        rules_dir = tmp_path / "rules"
        core_dir = rules_dir / "core" / "structure"
        _create_rule(core_dir, "CORE:S:0001", "Size Limits")

        docs_dir = rules_dir / "docs"
        docs_dir.mkdir(parents=True)
        (docs_dir / "sources.yml").write_text("general:\n  - id: anthropic-docs\n    weight: 1.0\n")

        project = tmp_path / "project"
        config_dir = project / ".reporails"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yml").write_text("disabled_rules:\n  - NOPE\n")

        rules = load_rules(
            rules_paths=[rules_dir],
            include_experimental=True,
            project_root=project,
        )
        assert "CORE:S:0001" in rules

    def test_no_project_root_backward_compat(self, tmp_path: Path) -> None:
        from reporails_cli.core.registry import load_rules

        rules_dir = tmp_path / "rules"
        core_dir = rules_dir / "core" / "structure"
        _create_rule(core_dir, "CORE:S:0001", "Size Limits")

        docs_dir = rules_dir / "docs"
        docs_dir.mkdir(parents=True)
        (docs_dir / "sources.yml").write_text("general:\n  - id: anthropic-docs\n    weight: 1.0\n")

        # No project_root — backward compatible
        rules = load_rules(rules_paths=[rules_dir], include_experimental=True)
        assert "CORE:S:0001" in rules
