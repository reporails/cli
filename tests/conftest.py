"""Pytest fixtures for reporails test suite.

Provides reusable fixtures for testing rule validation and scoring.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import pytest

# Tests never download the model set: a runner without the in-tree model (CI)
# runs without it, as `ails check` does offline. Set at import so `ails`
# subprocesses inherit it; a test of the download path unsets it.
os.environ.setdefault("AILS_MODEL_OFFLINE", "1")
# Tests never reach the hosted diagnostics service: with `AILS_SERVER_URL` unset, every
# `ails check` a test runs would be sent there. A closed local port fails fast, so a check
# runs its offline path; a test that needs a diagnostics endpoint sets its own.
os.environ.setdefault("AILS_SERVER_URL", "http://127.0.0.1:9")


@pytest.fixture(autouse=True)
def _isolate_home(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Generator[None, None, None]:
    """Isolate HOME so a developer's global config can't leak into discovery.

    A real `~/.reporails/config.yml` (`default_agent`), `~/.codex/`, or
    `~/.claude/` on the contributor's machine otherwise alters agent detection
    and config merge, making detection tests pass in clean CI but fail locally.
    Points HOME and the frozen `REPORAILS_HOME` constant at a fresh temp dir so
    every test sees the clean-HOME baseline CI runs under.

    On teardown, reap any mapper daemon this test forked. Each test gets a fresh
    HOME, so a cold `ails check` sees no running daemon and forks a new one
    (~500MB, model-loading) under this test's isolated home. With no teardown those
    daemons accumulate across the run — dozens of ~500MB processes that can exhaust
    the machine. Reaping here (while HOME still points at this test's dir, so the
    right socket is targeted) bounds concurrent daemons to at most one.
    """
    from reporails_cli.core.platform.config import bootstrap

    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(bootstrap, "REPORAILS_HOME", home / ".reporails")
    yield
    try:
        from reporails_cli.core.mapper.daemon import is_daemon_running, stop_daemon

        if is_daemon_running():
            stop_daemon()
    except Exception:
        pass


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register custom CLI options."""
    parser.addoption(
        "--update-golden",
        action="store_true",
        default=False,
        help="Regenerate golden snapshot expected.json files",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip tests marked `requires_model` when the in-tree model set is absent.

    A runner without the model files (CI) runs the rest of the suite and skips
    exactly the tests that need the mapper model, as `ails check` runs without it.
    """
    from reporails_cli.bundled import get_bundled_path
    from reporails_cli.core.mapper.model_fetch import models_present

    if models_present(get_bundled_path() / "models"):
        return
    skip = pytest.mark.skip(reason="Bundled mapper model not available")
    for item in items:
        if item.get_closest_marker("requires_model"):
            item.add_marker(skip)


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
    """Path to development rules directory (bundled in-repo).

    Skip if not available (e.g. rules not yet copied into repo).
    """
    cli_dir = Path(__file__).resolve().parents[1]  # cli/
    rules_dir = cli_dir / "framework" / "rules"
    if not rules_dir.exists() or not (rules_dir / "core").exists():
        pytest.skip("Development rules directory not available")
    return rules_dir


@pytest.fixture
def agent_file_types() -> list:
    """Return Claude agent file type declarations.

    Skips when framework is not installed (CI without ~/.reporails/rules/).
    """
    from reporails_cli.core.classify import load_file_types

    result = load_file_types("claude")
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

1. Read `.ails/backbone.yml`
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

    # Create skills directory (L5 gate: dynamic_context)
    skills_dir = project / ".claude" / "skills"
    skills_dir.mkdir(parents=True, exist_ok=True)
    (skills_dir / "example.md").write_text("# Example skill\n")

    # Create .ails directory with backbone
    ails_dir = project / ".ails"
    ails_dir.mkdir()

    (ails_dir / "backbone.yml").write_text("""\
# Auto-generated by ails map. Customize freely.
version: 3
generator: ails map
agents:
  claude:
    main_instruction_file: CLAUDE.md
    rules: .claude/rules/
    skills: .claude/skills/
""")

    yield project


# --- Rule YAML Fixtures ---


@pytest.fixture
def valid_rule_yaml() -> str:
    """Return a valid checks YAML."""
    return """\
checks:
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
checks:
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
checks:
  - id: test-invalid-toplevel
    message: "Invalid schema"
    severity: WARNING
    languages: [generic]
    pattern-not-regex: "something"
    paths:
      include:
        - "**/*.md"
"""


# --- Helper Functions ---


def create_temp_rule_file(tmp_path: Path, content: str, name: str = "test-rule.yml") -> Path:
    """Create a temporary rule YAML file."""
    rule_path = tmp_path / name
    rule_path.write_text(content)
    return rule_path
