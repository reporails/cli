"""Pytest fixtures for reporails test suite.

Provides reusable fixtures for testing template resolution, rule validation,
capability detection, and scoring.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register custom CLI options."""
    parser.addoption(
        "--update-golden",
        action="store_true",
        default=False,
        help="Regenerate golden snapshot expected.json files",
    )


@pytest.fixture
def update_golden(request: pytest.FixtureRequest) -> bool:
    """Whether to update golden snapshot files instead of comparing."""
    return bool(request.config.getoption("--update-golden"))


# Path to test fixtures
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def dev_rules_dir() -> Path:
    """Path to development rules directory (framework repo).

    Skip if not available (CI environments without the monorepo).
    """
    # Walk up from cli/ to find rules/ sibling
    cli_dir = Path(__file__).resolve().parents[1]  # cli/
    rules_dir = cli_dir.parent / "rules"
    if not rules_dir.exists() or not (rules_dir / "core").exists():
        pytest.skip("Development rules directory not available")
    return rules_dir


@pytest.fixture
def agent_config() -> dict[str, str]:
    """Return Claude agent template variables.

    Skips when framework is not installed (CI without ~/.reporails/rules/).
    """
    from reporails_cli.core.bootstrap import get_agent_vars

    result = get_agent_vars("claude")
    if not result:
        pytest.skip("Framework not installed (no agent config available)")
    return result


@pytest.fixture
def temp_project(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a minimal temporary project directory."""
    project = tmp_path / "test_project"
    project.mkdir()

    # Create minimal CLAUDE.md
    claude_md = project / "CLAUDE.md"
    claude_md.write_text("# Test Project\n\nThis is a test project.\n")

    yield project

    # Cleanup handled by tmp_path fixture


@pytest.fixture
def level1_project(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a Level 1 (minimal) project — single AGENTS.md."""
    project = tmp_path / "level1"
    project.mkdir()

    (project / "AGENTS.md").write_text("# My Project\n\nA simple project.\n")

    yield project


@pytest.fixture
def level2_project(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a Level 2 (basic) project — AGENTS.md + CLAUDE.md with sections.

    AGENTS.md is scanned by the generic default (no --agent).
    CLAUDE.md is scanned when tests pass --agent claude.
    """
    project = tmp_path / "level2"
    project.mkdir()

    content = """\
# My Project

A project with structure.

## Commands

- `npm install` - Install dependencies
- `npm test` - Run tests

## Architecture

The project uses a modular architecture.

## Constraints

- MUST use TypeScript
- NEVER commit secrets
"""
    (project / "AGENTS.md").write_text(content)
    (project / "CLAUDE.md").write_text(content)

    yield project


@pytest.fixture
def level3_project(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a Level 3 (structured) project - CLAUDE.md + rules dir."""
    project = tmp_path / "level3"
    project.mkdir()

    (project / "CLAUDE.md").write_text("""\
# My Project

A structured project.

## Commands

- `npm install` - Install dependencies
- MUST run linter before committing

## Architecture

Read `.claude/rules/` for detailed rules.
""")

    # Create rules directory
    rules_dir = project / ".claude" / "rules"
    rules_dir.mkdir(parents=True)

    (rules_dir / "testing.md").write_text("""\
# Testing Rules

- MUST write tests for new features
- NEVER skip failing tests
""")

    yield project


@pytest.fixture
def level5_project(tmp_path: Path) -> Generator[Path, None, None]:
    """Create a Level 5 (governed) project - full setup with backbone."""
    project = tmp_path / "level5"
    project.mkdir()

    (project / "CLAUDE.md").write_text("""\
# My Project

A governed project with full structure.

## Session Start

1. Read `.reporails/backbone.yml`
2. Check project status

## Commands

- `npm install` - Install dependencies
- NEVER push directly to main

## Architecture

See component documentation.
""")

    # Create rules directory
    rules_dir = project / ".claude" / "rules"
    rules_dir.mkdir(parents=True)

    (rules_dir / "security.md").write_text("""\
# Security Rules

- MUST validate all inputs
- NEVER log secrets
""")

    (rules_dir / "testing.md").write_text("""\
# Testing Rules

- MUST write tests for new features
""")

    # Create .reporails directory with backbone
    reporails_dir = project / ".reporails"
    reporails_dir.mkdir()

    (reporails_dir / "backbone.yml").write_text("""\
# Auto-generated by ails map. Customize freely.
version: 2
generator: ails map
agents:
  claude:
    main_instruction_file: CLAUDE.md
    rules: .claude/rules/
""")

    yield project


# --- Rule YAML Fixtures ---


@pytest.fixture
def valid_rule_yaml() -> str:
    """Return a valid OpenGrep rule YAML."""
    return """\
rules:
  - id: test-valid-rule
    message: "Found a TODO comment"
    severity: WARNING
    languages: [generic]
    pattern-regex: "TODO"
    paths:
      include:
        - "**/*.md"
"""


@pytest.fixture
def valid_rule_with_patterns_yaml() -> str:
    """Return a valid rule using patterns block."""
    return """\
rules:
  - id: test-patterns-rule
    message: "File missing required section"
    severity: WARNING
    languages: [generic]
    patterns:
      - pattern-regex: "."
      - pattern-not-regex: "## Commands"
    paths:
      include:
        - "**/*.md"
"""


@pytest.fixture
def invalid_toplevel_pattern_not_regex_yaml() -> str:
    """Return an INVALID rule with pattern-not-regex at top level.

    This is the bug we found - pattern-not-regex requires patterns: block.
    """
    return """\
rules:
  - id: test-invalid-toplevel
    message: "Invalid schema"
    severity: WARNING
    languages: [generic]
    pattern-not-regex: "something"
    paths:
      include:
        - "**/*.md"
"""


@pytest.fixture
def rule_with_template_yaml() -> str:
    """Return a rule with template placeholder."""
    return """\
rules:
  - id: test-template-rule
    message: "Found match"
    severity: WARNING
    languages: [generic]
    pattern-regex: "MUST"
    paths:
      include:
        - "{{instruction_files}}"
"""


@pytest.fixture
def rule_with_unresolvable_template_yaml() -> str:
    """Return a rule with a template that won't resolve."""
    return """\
rules:
  - id: test-unresolvable
    message: "Unresolvable template"
    severity: WARNING
    languages: [generic]
    pattern-regex: "test"
    paths:
      include:
        - "{{nonexistent_variable}}"
"""


# --- Helper Functions ---


def create_temp_rule_file(tmp_path: Path, content: str, name: str = "test-rule.yml") -> Path:
    """Create a temporary rule YAML file."""
    rule_path = tmp_path / name
    rule_path.write_text(content)
    return rule_path
