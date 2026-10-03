"""The credential rule's pattern: secret values that start with a symbol are caught, documented type fields are not."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from reporails_cli.core.lint.regex import run_checks

_CHECKS = Path(__file__).resolve().parents[2] / "framework" / "rules" / "core" / "no-credentials" / "checks.yml"


def _pattern() -> re.Pattern[str]:
    checks = yaml.safe_load(_CHECKS.read_text())["checks"]
    return re.compile(next(c["pattern-regex"] for c in checks if c["id"].endswith("pattern_check")))


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    "line",
    [
        'secret_key: "+Zk2/abc"',
        'secret_key = "/9aB+"',
        "SECRET_KEY=$(cat key)",
        'secret_key = "sk-live-abc123"',
        "secret-key: abc123",
        'password = "/9aB+"',
        'api_key: "+Zk2/abc"',
    ],
)
def test_secret_key_value_is_caught(line: str) -> None:
    assert _pattern().search(line), line


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    "line",
    [
        "    secret_key: str",
        "    secret_key: Optional[str] = None",
        "secret_key: int",
        'secret_key = ""',
        "secret_key =",
    ],
)
def test_documented_type_field_or_empty_value_is_not_flagged(line: str) -> None:
    assert not _pattern().search(line), line


_SK = "sk-live-" + "a" * 24
_GHP = "ghp_" + "b" * 36


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    "line",
    [
        f"Use the key `{_SK}` for the deploy API.",
        f"token {_GHP}",
        "The fine-grained token is github_pat_" + "c" * 30,
        "Access key id AKIA0000000000000000 for the bucket.",
        "Slack bot token xoxb-0000000000-aaaaaaaaaaaa",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "sk-" + "a" * 48,
        'password = "hunter2hunter2"',
        'password: "hunter2hunter2"',
    ],
)
def test_key_shape_is_caught_wherever_it_stands(line: str) -> None:
    assert _pattern().search(line), line


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    "line",
    [
        "Keys look like sk-... or ghp_... here.",
        "Put it in <your-key>, xxxx or YOUR_API_KEY.",
        "sk-live-<your-key>",
        "sk-live-YOUR_API_KEY_GOES_HERE_PLEASE",
        "ghp_" + "x" * 36,
        "AKIAIOSFODNN7EXAMPLE",
        "xoxb-your-token-here",
        "the task-based-orchestration-of-many-independent-workers",
        "risk-assessment-of-the-whole-deployment-pipeline",
        "async login(username: string, password: string) {",
        "password: string",
        "password: str",
        "password?: string",
        "String password",
        "String password;",
        "password = null",
        "password: Optional[str]",
    ],
)
def test_placeholder_word_or_typed_declaration_is_not_flagged(line: str) -> None:
    assert not _pattern().search(line), line


def _scan(project: Path, *files: str) -> list[tuple[str, int]]:
    findings = run_checks([_CHECKS], project, instruction_files=[project / f for f in files])
    return sorted((f.file, f.line) for f in findings if f.rule == "CORE:G:0002")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_every_secret_line_is_reported_in_one_run(tmp_path: Path) -> None:
    lines = [
        "# Notes",
        "",
        "intro",
        "",
        f'api_key = "{_SK}"',
        "",
        "text",
        "",
        f"The token is {_GHP}.",
        "",
        'password: "hunter2hunter2"',
    ]
    (tmp_path / "CLAUDE.md").write_text("\n".join(lines) + "\n")
    assert _scan(tmp_path, "CLAUDE.md") == [("CLAUDE.md", 5), ("CLAUDE.md", 9), ("CLAUDE.md", 11)]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_secret_in_imported_file_is_reported_on_the_imported_file(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "more.md").write_text(f'# More\n\ntext\n\napi_key = "{_SK}"\n')
    (tmp_path / "CLAUDE.md").write_text(f"# Project\n\n@docs/more.md\n\nThe token is {_GHP}.\n")
    assert _scan(tmp_path, "CLAUDE.md") == [("CLAUDE.md", 5), ("docs/more.md", 5)]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_secret_in_file_also_scanned_directly_is_reported_once(tmp_path: Path) -> None:
    (tmp_path / "more.md").write_text(f'api_key = "{_SK}"\n')
    (tmp_path / "CLAUDE.md").write_text("@more.md\n")
    assert _scan(tmp_path, "CLAUDE.md", "more.md") == [("more.md", 1)]
