"""Mutation-killing behavioral tests for `mechanical/checks.py`.

Targets survivors in `frontmatter_key`
(L233, L237), `line_count` below-min + read-error (L277, L282), and
`byte_size` below-min (L302).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.lint.mechanical.checks import (
    byte_size,
    frontmatter_key,
    line_count,
)
from reporails_cli.core.platform.dto.models import ClassifiedFile


def _cf(root: Path, *rel_paths: str, file_type: str = "main") -> list[ClassifiedFile]:
    return [ClassifiedFile(path=root / p, file_type=file_type) for p in rel_paths]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_frontmatter_key_found_passes(tmp_path: Path) -> None:
    # Kills L233 `passed=True -> False`: a present frontmatter key passes.
    (tmp_path / "CLAUDE.md").write_text("---\nname: demo\n---\n# Body\n")
    result = frontmatter_key(tmp_path, {"key": "name"}, _cf(tmp_path, "CLAUDE.md"))
    assert result.passed is True


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_frontmatter_key_missing_fails(tmp_path: Path) -> None:
    # Kills L237 `passed=False -> True`: an absent frontmatter key fails.
    (tmp_path / "CLAUDE.md").write_text("---\ntitle: demo\n---\n# Body\n")
    result = frontmatter_key(tmp_path, {"key": "name"}, _cf(tmp_path, "CLAUDE.md"))
    assert result.passed is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_line_count_below_min_fails(tmp_path: Path) -> None:
    # Kills L277 `passed=False -> True`: a file below the min line count fails.
    (tmp_path / "CLAUDE.md").write_text("only one line\n")
    result = line_count(tmp_path, {"min": 5}, _cf(tmp_path, "CLAUDE.md"))
    assert result.passed is False
    assert "below min" in result.message


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file-permission read errors")
def test_line_count_read_error_fails(tmp_path: Path) -> None:
    # Kills L282 `passed=False -> True`: an unreadable file yields a failing read-error result.
    target = tmp_path / "CLAUDE.md"
    target.write_text("some content\nmore\n")
    os.chmod(target, 0o000)
    try:
        result = line_count(tmp_path, {"max": 100}, _cf(tmp_path, "CLAUDE.md"))
        assert result.passed is False
        assert "Error reading" in result.message
    finally:
        os.chmod(target, 0o644)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_byte_size_below_min_fails(tmp_path: Path) -> None:
    # Kills L302 `passed=False -> True`: a file below the min byte size fails.
    (tmp_path / "CLAUDE.md").write_text("tiny")
    result = byte_size(tmp_path, {"min": 1000}, _cf(tmp_path, "CLAUDE.md"))
    assert result.passed is False
    assert "below min" in result.message
