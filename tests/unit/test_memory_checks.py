"""Tests for core/lint/memory_checks.py — memory index link + frontmatter checks.

A SEAM per file: feed a memory index that names a broken link, or that names a
memory file with no valid frontmatter, and assert the real rule id each finding
carries — a broken link is `CORE:S:0056` (Markdown Link Targets Resolve, the
shipped rule whose `match` is unrestricted on file type); a missing/incomplete
frontmatter carries the `memory_frontmatter` theory label because no shipped
rule requires frontmatter on a memory-typed file (the two frontmatter-identity
rules match `type: rules` only). Feeding a well-formed index asserts no finding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.memory_checks import validate_memory_files
from reporails_cli.core.platform.dto.ruleset import FileRecord


def _memory(path: Path, file_type: str = "memory") -> list[FileRecord]:
    return [FileRecord(path=path.as_posix(), content_hash="sha256:0", type=file_type)]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_broken_memory_link_reports_the_real_markdown_link_rule(tmp_path: Path) -> None:
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    index = memory_dir / "MEMORY.md"
    index.write_text("# Memory\n\n- [Missing](missing.md) — never written\n", encoding="utf-8")

    findings = validate_memory_files(_memory(index))

    assert len(findings) == 1
    assert findings[0].rule == "CORE:S:0056"
    assert findings[0].severity == "error"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_memory_file_missing_frontmatter_reports_the_theory_label(tmp_path: Path) -> None:
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    (memory_dir / "feedback_example.md").write_text("Just prose, no frontmatter.\n", encoding="utf-8")
    index = memory_dir / "MEMORY.md"
    index.write_text("# Memory\n\n- [Example](feedback_example.md) — a note\n", encoding="utf-8")

    findings = validate_memory_files(_memory(index))

    assert len(findings) == 1
    assert findings[0].rule == "memory_frontmatter"
    assert findings[0].severity == "warning"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_well_formed_memory_index_reports_nothing(tmp_path: Path) -> None:
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    (memory_dir / "feedback_example.md").write_text(
        "---\nname: feedback_example\ndescription: An example memory\ntype: memory\n---\n\nBody.\n",
        encoding="utf-8",
    )
    index = memory_dir / "MEMORY.md"
    index.write_text("# Memory\n\n- [Example](feedback_example.md) — a note\n", encoding="utf-8")

    findings = validate_memory_files(_memory(index))

    assert findings == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_memory_file_frontmatter_that_is_not_yaml_is_a_finding_on_its_index_line(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    (memory_dir / "note.md").write_text("---\nname: [unclosed\ndescription: x\n---\nbody\n", encoding="utf-8")
    index = memory_dir / "MEMORY.md"
    index.write_text("# Memory\n\n- [Note](note.md) — a note\n", encoding="utf-8")

    findings = validate_memory_files(_memory(index))

    assert len(findings) == 1
    assert findings[0].rule == "memory_frontmatter"
    assert findings[0].line == 3
    assert "`note.md`" in findings[0].message
    assert "not valid YAML" in findings[0].message
    assert caplog.text == ""


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_memory_link_shown_as_code_is_not_a_link(tmp_path: Path) -> None:
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    index = memory_dir / "MEMORY.md"
    index.write_text("# Memory\n\nWrite `[x](example.md)` like this.\n\n```\n[y](other.md)\n```\n", encoding="utf-8")

    assert validate_memory_files(_memory(index)) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_instruction_file_in_a_folder_named_memory_is_not_a_memory_index(tmp_path: Path) -> None:
    folder = tmp_path / "rv-memory-cache"
    folder.mkdir()
    index = folder / "CLAUDE.md"
    index.write_text("Read [setup](docs/setup.md) before you start.\n", encoding="utf-8")
    (folder / "docs").mkdir()
    (folder / "docs" / "setup.md").write_text("No frontmatter.\n", encoding="utf-8")

    assert validate_memory_files(_memory(index, "main")) == []
    assert validate_memory_files(_memory(index, "memory")) != []


def _frontmatter_findings(tmp_path: Path, body: str) -> list[str]:
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    (memory_dir / "note.md").write_text(body, encoding="utf-8")
    index = memory_dir / "MEMORY.md"
    index.write_text("- [Note](note.md)\n", encoding="utf-8")
    return [f.message for f in validate_memory_files(_memory(index))]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_memory_file_opening_with_a_rule_line_has_no_frontmatter_not_an_unclosed_one(tmp_path: Path) -> None:
    messages = _frontmatter_findings(tmp_path, "----\nBody.\n")

    assert len(messages) == 1 and "has no frontmatter" in messages[0]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_empty_memory_frontmatter_block_reports_the_missing_fields(tmp_path: Path) -> None:
    messages = _frontmatter_findings(tmp_path, "---\n---\nBody.\n")

    assert messages == ["`note.md` missing frontmatter: description, name, type."]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_memory_frontmatter_holding_a_list_is_not_called_invalid_yaml(tmp_path: Path) -> None:
    messages = _frontmatter_findings(tmp_path, "---\n- a\n- b\n---\nBody.\n")

    assert len(messages) == 1 and "not valid YAML" not in messages[0] and "not a mapping" in messages[0]
