"""Unit tests for discover.py — backbone v3 detection functions."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from reporails_cli.core.discover import (
    _detect_classification,
    _detect_commands,
    _detect_meta,
    _detect_paths,
    generate_backbone_placeholder,
    generate_backbone_yaml,
)

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


class TestDetectClassification:
    def test_python_cli_project(self, tmp_path: Path) -> None:
        """pyproject.toml with scripts → type=cli, language=[python]."""
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "myapp"\nversion = "1.0"\n'
            'dependencies = ["click"]\n'
            '[project.scripts]\nmyapp = "myapp:main"\n'
        )
        result = _detect_classification(tmp_path)
        assert result["type"] == "cli"
        assert result["language"] == ["python"]
        assert result["runtime"] == "cpython"

    def test_python_library_project(self, tmp_path: Path) -> None:
        """pyproject.toml without scripts → type=library."""
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "mylib"\nversion = "1.0"\n')
        result = _detect_classification(tmp_path)
        assert result["type"] == "library"
        assert result["language"] == ["python"]

    def test_node_project(self, tmp_path: Path) -> None:
        """package.json → language=[javascript]."""
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        (tmp_path / "package.json").write_text(json.dumps({"name": "myapp", "version": "1.0"}))
        result = _detect_classification(tmp_path)
        assert result["language"] == ["javascript"]
        assert result["runtime"] == "node"

    def test_typescript_detection(self, tmp_path: Path) -> None:
        """package.json + tsconfig.json → language=[typescript]."""
        (tmp_path / "src").mkdir()
        (tmp_path / "package.json").write_text(json.dumps({"name": "myapp"}))
        (tmp_path / "tsconfig.json").write_text("{}")
        result = _detect_classification(tmp_path)
        assert result["language"] == ["typescript"]

    def test_bun_runtime_detection(self, tmp_path: Path) -> None:
        """bun.lockb → runtime=bun."""
        (tmp_path / "package.json").write_text(json.dumps({"name": "myapp"}))
        (tmp_path / "bun.lockb").write_bytes(b"")
        result = _detect_classification(tmp_path)
        assert result["runtime"] == "bun"

    def test_deno_runtime_detection(self, tmp_path: Path) -> None:
        """deno.lock → runtime=deno."""
        (tmp_path / "package.json").write_text(json.dumps({"name": "myapp"}))
        (tmp_path / "deno.lock").write_text("{}")
        result = _detect_classification(tmp_path)
        assert result["runtime"] == "deno"

    def test_multi_language(self, tmp_path: Path) -> None:
        """Both pyproject.toml + package.json → multi-language."""
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "myapp"\n')
        (tmp_path / "package.json").write_text(json.dumps({"name": "frontend"}))
        result = _detect_classification(tmp_path)
        assert "python" in result["language"]
        assert "javascript" in result["language"]

    def test_empty_project(self, tmp_path: Path) -> None:
        """No manifests → all null."""
        result = _detect_classification(tmp_path)
        assert result["type"] is None
        assert result["language"] is None
        assert result["framework"] is None
        assert result["runtime"] is None

    def test_framework_detection_fastapi(self, tmp_path: Path) -> None:
        """FastAPI in dependencies → framework=fastapi."""
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "api"\ndependencies = ["fastapi>=0.100"]\n')
        result = _detect_classification(tmp_path)
        assert result["framework"] == "fastapi"

    def test_framework_detection_express(self, tmp_path: Path) -> None:
        """Express in dependencies → framework=express."""
        (tmp_path / "package.json").write_text(json.dumps({"name": "api", "dependencies": {"express": "^4.0"}}))
        result = _detect_classification(tmp_path)
        assert result["framework"] == "express"

    def test_monorepo_npm_workspaces(self, tmp_path: Path) -> None:
        """package.json with workspaces → type=monorepo."""
        (tmp_path / "package.json").write_text(json.dumps({"name": "mono", "workspaces": ["packages/*"]}))
        result = _detect_classification(tmp_path)
        assert result["type"] == "monorepo"

    def test_app_directory(self, tmp_path: Path) -> None:
        """app/ directory → type=app."""
        (tmp_path / "app").mkdir()
        (tmp_path / "package.json").write_text(json.dumps({"name": "myapp"}))
        result = _detect_classification(tmp_path)
        assert result["type"] == "app"

    def test_rust_project(self, tmp_path: Path) -> None:
        """Cargo.toml → language=[rust]."""
        (tmp_path / "Cargo.toml").write_text('[package]\nname = "mylib"\nversion = "0.1.0"\n')
        result = _detect_classification(tmp_path)
        assert result["language"] == ["rust"]

    def test_go_project(self, tmp_path: Path) -> None:
        """go.mod → language=[go]."""
        (tmp_path / "go.mod").write_text("module example.com/mymod\n\ngo 1.21\n")
        result = _detect_classification(tmp_path)
        assert result["language"] == ["go"]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


class TestDetectCommands:
    def test_makefile_targets(self, tmp_path: Path) -> None:
        """Makefile with standard targets."""
        (tmp_path / "Makefile").write_text(
            "build:\n\tgo build\n\ntest:\n\tgo test ./...\n\nlint:\n\tgolangci-lint run\n"
        )
        result = _detect_commands(tmp_path)
        assert result["build"] == "make build"
        assert result["test"] == "make test"
        assert result["lint"] == "make lint"

    def test_pyproject_poe_tasks(self, tmp_path: Path) -> None:
        """Poe tasks in pyproject.toml."""
        (tmp_path / "pyproject.toml").write_text(
            '[tool.poe.tasks]\ntest = "pytest"\nlint = "ruff check"\nformat = "ruff format"\n'
        )
        result = _detect_commands(tmp_path)
        assert result["test"] == "poe test"
        assert result["lint"] == "poe lint"
        assert result["format"] == "poe format"

    def test_package_json_scripts(self, tmp_path: Path) -> None:
        """npm scripts in package.json."""
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "scripts": {
                        "build": "tsc",
                        "test": "jest",
                        "lint": "eslint .",
                        "format": "prettier --write .",
                    }
                }
            )
        )
        result = _detect_commands(tmp_path)
        assert result["build"] == "npm run build"
        assert result["test"] == "npm run test"
        assert result["lint"] == "npm run lint"
        assert result["format"] == "npm run format"

    def test_infer_pytest_from_config(self, tmp_path: Path) -> None:
        """pytest config in pyproject.toml → test=pytest."""
        (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\naddopts = '-v'\n")
        result = _detect_commands(tmp_path)
        assert result["test"] == "pytest"

    def test_infer_ruff_from_config(self, tmp_path: Path) -> None:
        """ruff.toml exists → lint=ruff check, format=ruff format."""
        (tmp_path / "ruff.toml").write_text("[lint]\nselect = ['E']\n")
        result = _detect_commands(tmp_path)
        assert result["lint"] == "ruff check"
        assert result["format"] == "ruff format"

    def test_empty_project(self, tmp_path: Path) -> None:
        """No task runners or configs → all null."""
        result = _detect_commands(tmp_path)
        assert all(v is None for v in result.values())

    def test_poe_takes_priority_over_npm(self, tmp_path: Path) -> None:
        """Poe tasks win over npm scripts."""
        (tmp_path / "pyproject.toml").write_text("[tool.poe.tasks]\ntest = 'pytest'\n")
        (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "jest"}}))
        result = _detect_commands(tmp_path)
        assert result["test"] == "poe test"


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------


class TestDetectMeta:
    def test_finds_version_and_changelog(self, tmp_path: Path) -> None:
        """VERSION + CHANGELOG.md detected."""
        (tmp_path / "VERSION").write_text("1.0.0\n")
        (tmp_path / "CHANGELOG.md").write_text("# Changelog\n")
        result = _detect_meta(tmp_path)
        assert result["version_file"] == "VERSION"
        assert result["changelog"] == "CHANGELOG.md"

    def test_manifest_priority(self, tmp_path: Path) -> None:
        """pyproject.toml wins over package.json."""
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
        (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
        result = _detect_meta(tmp_path)
        assert result["manifest"] == "pyproject.toml"

    def test_version_from_manifest(self, tmp_path: Path) -> None:
        """No VERSION file → falls back to manifest version field."""
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "2.0"\n')
        result = _detect_meta(tmp_path)
        assert result["version_file"] == "pyproject.toml"

    def test_ci_github_actions(self, tmp_path: Path) -> None:
        """GitHub Actions workflows detected."""
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        result = _detect_meta(tmp_path)
        assert result["ci"] == ".github/workflows/"

    def test_ci_gitlab(self, tmp_path: Path) -> None:
        """.gitlab-ci.yml detected."""
        (tmp_path / ".gitlab-ci.yml").write_text("stages: [build]\n")
        result = _detect_meta(tmp_path)
        assert result["ci"] == ".gitlab-ci.yml"

    def test_unreleased_changelog(self, tmp_path: Path) -> None:
        """UNRELEASED.md detected as changelog (second priority)."""
        (tmp_path / "UNRELEASED.md").write_text("# Unreleased\n")
        result = _detect_meta(tmp_path)
        assert result["changelog"] == "UNRELEASED.md"

    def test_empty_project(self, tmp_path: Path) -> None:
        """No files → all null."""
        result = _detect_meta(tmp_path)
        assert all(v is None for v in result.values())


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


class TestDetectPaths:
    def test_standard_layout(self, tmp_path: Path) -> None:
        """src/ + tests/ + docs/ detected."""
        (tmp_path / "src" / "mypackage").mkdir(parents=True)
        (tmp_path / "tests").mkdir()
        (tmp_path / "docs").mkdir()
        result = _detect_paths(tmp_path)
        assert result["src"] == "src/mypackage/"
        assert result["tests"] == "tests/"
        assert result["docs"] == "docs/"

    def test_src_no_deep_resolve_with_multiple_children(self, tmp_path: Path) -> None:
        """src/ with multiple children → src/ not resolved deeper."""
        (tmp_path / "src" / "a").mkdir(parents=True)
        (tmp_path / "src" / "b").mkdir()
        result = _detect_paths(tmp_path)
        assert result["src"] == "src/"

    def test_lib_as_source(self, tmp_path: Path) -> None:
        """lib/ detected as src when no src/ exists."""
        (tmp_path / "lib").mkdir()
        result = _detect_paths(tmp_path)
        assert result["src"] == "lib/"

    def test_scripts_detection(self, tmp_path: Path) -> None:
        """scripts/ detected."""
        (tmp_path / "scripts").mkdir()
        result = _detect_paths(tmp_path)
        assert result["scripts"] == "scripts/"

    def test_empty_project(self, tmp_path: Path) -> None:
        """No directories → all null."""
        result = _detect_paths(tmp_path)
        assert all(v is None for v in result.values())


# ---------------------------------------------------------------------------
# Full backbone generation
# ---------------------------------------------------------------------------


class TestGenerateBackboneV3:
    def test_version_3(self, tmp_path: Path) -> None:
        """Generated backbone has version 3."""
        from reporails_cli.core.agents import DetectedAgent, get_known_agents

        agent = DetectedAgent(
            agent_type=get_known_agents()["claude"],
            instruction_files=[tmp_path / "CLAUDE.md"],
        )
        output = generate_backbone_yaml(tmp_path, [agent])
        data = yaml.safe_load(output)
        assert data["version"] == 3

    def test_all_v3_sections_present(self, tmp_path: Path) -> None:
        """v3 backbone has identity, agents, paths (three dimensions)."""
        (tmp_path / "CLAUDE.md").write_text("# Test\n")
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()

        from reporails_cli.core.agents import DetectedAgent, get_known_agents

        agent = DetectedAgent(
            agent_type=get_known_agents()["claude"],
            instruction_files=[tmp_path / "CLAUDE.md"],
        )
        output = generate_backbone_yaml(tmp_path, [agent])
        data = yaml.safe_load(output)

        assert data["version"] == 3
        assert "auto_heal" in data
        assert data["auto_heal"] is True
        assert "directive" in data
        assert "identity" in data
        assert "agents" in data
        assert "paths" in data

    def test_null_leaves_stripped(self, tmp_path: Path) -> None:
        """Null values are stripped from YAML output."""
        output = generate_backbone_yaml(tmp_path, [])
        data = yaml.safe_load(output)
        # Empty project — no classification keys with null values should appear
        assert "identity" not in data or all(v is not None for v in (data.get("identity") or {}).values())

    def test_header_comment(self, tmp_path: Path) -> None:
        """Output starts with header comment referencing v3."""
        output = generate_backbone_yaml(tmp_path, [])
        assert output.startswith("# Auto-generated by ails map")
        assert "backbone v3" in output

    def test_agents_section_populated(self, tmp_path: Path) -> None:
        """Agents section populated from detected agents."""
        (tmp_path / "CLAUDE.md").write_text("# Test\n")

        from reporails_cli.core.agents import DetectedAgent, get_known_agents

        agent = DetectedAgent(
            agent_type=get_known_agents()["claude"],
            instruction_files=[tmp_path / "CLAUDE.md"],
            detected_directories={"rules": ".claude/rules/"},
        )
        output = generate_backbone_yaml(tmp_path, [agent])
        data = yaml.safe_load(output)

        assert "claude" in data["agents"]
        assert data["agents"]["claude"]["main_instruction_file"] == "CLAUDE.md"
        assert data["agents"]["claude"]["rules"] == ".claude/rules/"


class TestPlaceholder:
    def test_version_3(self) -> None:
        """Placeholder is version 3."""
        content = generate_backbone_placeholder()
        assert "version: 3" in content
