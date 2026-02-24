"""Unit tests for ails config set/get/list with --global flag."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.config_command import config_app

runner = CliRunner()


def _write_global_config(global_home: Path, content: str) -> Path:
    config_path = global_home / "config.yml"
    global_home.mkdir(parents=True, exist_ok=True)
    config_path.write_text(content, encoding="utf-8")
    return config_path


class TestGlobalSet:
    """Test config set --global."""

    def test_writes_to_home_config(self, tmp_path: Path) -> None:
        global_home = tmp_path / ".reporails"
        with patch(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            return_value=global_home / "config.yml",
        ):
            result = runner.invoke(config_app, ["set", "--global", "default_agent", "claude"])
        assert result.exit_code == 0
        assert "global" in result.output
        data = yaml.safe_load((global_home / "config.yml").read_text())
        assert data["default_agent"] == "claude"

    def test_writes_recommended_bool(self, tmp_path: Path) -> None:
        global_home = tmp_path / ".reporails"
        with patch(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            return_value=global_home / "config.yml",
        ):
            result = runner.invoke(config_app, ["set", "--global", "recommended", "false"])
        assert result.exit_code == 0
        data = yaml.safe_load((global_home / "config.yml").read_text())
        assert data["recommended"] is False

    def test_rejects_non_global_key(self) -> None:
        result = runner.invoke(config_app, ["set", "--global", "exclude_dirs", "vendor"])
        assert result.exit_code == 2
        assert "not supported in global config" in result.output

    def test_rejects_unknown_key(self) -> None:
        result = runner.invoke(config_app, ["set", "--global", "bogus", "val"])
        assert result.exit_code == 2
        assert "Unknown config key" in result.output


class TestGlobalGet:
    """Test config get --global."""

    def test_reads_from_home_config(self, tmp_path: Path) -> None:
        global_home = tmp_path / ".reporails"
        _write_global_config(global_home, "default_agent: cursor\n")
        with patch(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            return_value=global_home / "config.yml",
        ):
            result = runner.invoke(config_app, ["get", "--global", "default_agent"])
        assert result.exit_code == 0
        assert "cursor" in result.output

    def test_not_set(self, tmp_path: Path) -> None:
        global_home = tmp_path / ".reporails"
        global_home.mkdir(parents=True)
        with patch(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            return_value=global_home / "config.yml",
        ):
            result = runner.invoke(config_app, ["get", "--global", "default_agent"])
        assert result.exit_code == 0
        assert "not set" in result.output


class TestGlobalList:
    """Test config list --global."""

    def test_shows_global_only(self, tmp_path: Path) -> None:
        global_home = tmp_path / ".reporails"
        _write_global_config(global_home, "default_agent: claude\nrecommended: true\n")
        with patch(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            return_value=global_home / "config.yml",
        ):
            result = runner.invoke(config_app, ["list", "--global"])
        assert result.exit_code == 0
        assert "default_agent: claude" in result.output
        assert "recommended: True" in result.output

    def test_empty_global(self, tmp_path: Path) -> None:
        global_home = tmp_path / ".reporails"
        global_home.mkdir(parents=True)
        with patch(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            return_value=global_home / "config.yml",
        ):
            result = runner.invoke(config_app, ["list", "--global"])
        assert result.exit_code == 0
        assert "No global configuration set" in result.output


class TestListMerge:
    """Test config list shows global fallbacks annotated."""

    def test_shows_global_fallback_annotated(self, tmp_path: Path) -> None:
        # Project has exclude_dirs but no default_agent
        project = tmp_path / "project"
        cfg_dir = project / ".reporails"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "config.yml").write_text("exclude_dirs:\n  - vendor\n")

        global_home = tmp_path / ".reporails"
        _write_global_config(global_home, "default_agent: claude\n")

        with patch(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            return_value=global_home / "config.yml",
        ):
            result = runner.invoke(config_app, ["list", "--path", str(project)])
        assert result.exit_code == 0
        assert "default_agent: claude (global)" in result.output
        assert "exclude_dirs:" in result.output

    def test_project_value_not_annotated(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        cfg_dir = project / ".reporails"
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "config.yml").write_text("default_agent: cursor\n")

        global_home = tmp_path / ".reporails"
        _write_global_config(global_home, "default_agent: claude\n")

        with patch(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            return_value=global_home / "config.yml",
        ):
            result = runner.invoke(config_app, ["list", "--path", str(project)])
        assert result.exit_code == 0
        assert "default_agent: cursor" in result.output
        assert "(global)" not in result.output


class TestConfigEdgeCases:
    """Edge cases for config commands."""

    def test_set_overwrites_existing_value(self, tmp_path: Path) -> None:
        """Setting a key twice should persist the second value, not the first."""
        global_home = tmp_path / ".reporails"
        with patch(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            return_value=global_home / "config.yml",
        ):
            runner.invoke(config_app, ["set", "--global", "default_agent", "claude"])
            result = runner.invoke(config_app, ["set", "--global", "default_agent", "cursor"])

        assert result.exit_code == 0
        data = yaml.safe_load((global_home / "config.yml").read_text())
        assert data["default_agent"] == "cursor", f"Second set should overwrite first, got {data['default_agent']}"

    def test_malformed_global_config_handled(self, tmp_path: Path) -> None:
        """Malformed YAML in global config should not crash config list."""
        global_home = tmp_path / ".reporails"
        _write_global_config(global_home, "default_agent: [unclosed\n  bad: yaml: :\n")

        with patch(
            "reporails_cli.interfaces.cli.config_command._global_config_path",
            return_value=global_home / "config.yml",
        ):
            result = runner.invoke(config_app, ["list", "--global"])

        assert result.exit_code == 0, f"Should not crash on malformed YAML, got: {result.output}"
