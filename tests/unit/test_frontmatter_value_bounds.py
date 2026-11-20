"""`frontmatter_key` bounds the parsed value of a key: its length and a forbidden pattern."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.mechanical.checks import frontmatter_key
from reporails_cli.core.platform.dto.models import ClassifiedFile
from tests.unit.run_args import with_run_exclusions

_REL = ".claude/skills/example/SKILL.md"
_RESERVED = "(?i:anthropic|claude)"


def _skill(root: Path, text: str) -> list[ClassifiedFile]:
    path = root / _REL
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))
    return [ClassifiedFile(path=path, file_type="skill")]


def _name_check(root: Path, files: list[ClassifiedFile]) -> bool:
    args = {"key": "name", "max_length": 64, "value_pattern_absent": _RESERVED}
    return frontmatter_key(root, with_run_exclusions(root, args), files).passed


def _description_check(root: Path, files: list[ClassifiedFile]) -> bool:
    args = {"key": "description", "max_length": 1024}
    return frontmatter_key(root, with_run_exclusions(root, args), files).passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_crlf_value_at_the_limit_is_not_over_it(tmp_path: Path) -> None:
    exact = _skill(tmp_path, f"---\r\nname: {'a' * 64}\r\ndescription: {'b' * 1024}\r\n---\r\nbody\r\n")
    assert _name_check(tmp_path, exact)
    assert _description_check(tmp_path, exact)
    over = _skill(tmp_path, f"---\r\nname: {'a' * 65}\r\ndescription: {'b' * 1025}\r\n---\r\nbody\r\n")
    assert not _name_check(tmp_path, over)
    assert not _description_check(tmp_path, over)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_folded_block_counts_its_folded_text(tmp_path: Path) -> None:
    line = "b" * 60
    folded = "".join(f"    {line}\n" for _ in range(16))
    files = _skill(tmp_path, f"---\nname: example\ndescription: >\n{folded}---\nbody\n")
    assert _description_check(tmp_path, files)
    long_line = "c" * 70
    over = "".join(f"    {long_line}\n" for _ in range(16))
    assert not _description_check(tmp_path, _skill(tmp_path, f"---\nname: e\ndescription: >\n{over}---\nbody\n"))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_trailing_comment_is_not_part_of_the_value(tmp_path: Path) -> None:
    files = _skill(tmp_path, "---\nname: my-skill  # works with Claude Code\n---\nbody\n")
    assert _name_check(tmp_path, files)
    reserved = _skill(tmp_path, "---\nname: claude-helper  # fine\n---\nbody\n")
    assert not _name_check(tmp_path, reserved)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_missing_key_or_unreadable_block_is_not_a_bound_breach(tmp_path: Path) -> None:
    assert _name_check(tmp_path, _skill(tmp_path, "---\ndescription: x\n---\nbody\n"))
    assert _name_check(tmp_path, _skill(tmp_path, "---\nname: [unclosed\n---\nbody\n"))
