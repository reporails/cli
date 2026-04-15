"""Tests for the classification engine — content format detection and file matching."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classification import (
    classify_files,
    detect_content_format,
    match_files,
)
from reporails_cli.core.models import ClassifiedFile, FileMatch, FileTypeDeclaration

# ═══════════════════════════════════════════════════════════════════════
# detect_content_format — individual format detection
# ═══════════════════════════════════════════════════════════════════════


class TestDetectContentFormat:
    """Tests for detect_content_format() region detection."""

    @pytest.mark.parametrize(
        "text, expected_format",
        [
            ("# Title\n\nSome text.", "heading"),
            ("## Section\nContent here.", "heading"),
            ("###### Deep heading\n", "heading"),
        ],
        ids=["h1", "h2", "h6"],
    )
    def test_heading_detection(self, text: str, expected_format: str):
        result = detect_content_format(text)
        assert expected_format in result

    def test_heading_requires_space_after_hash(self):
        """#hashtag is not a heading."""
        result = detect_content_format("#hashtag not a heading\n")
        assert "heading" not in result

    @pytest.mark.parametrize(
        "text, expected_format",
        [
            ("```python\nprint('hi')\n```\n", "code_block"),
            ("```\nplain code\n```\n", "code_block"),
            ("~~~\nalt fence\n~~~\n", "code_block"),
        ],
        ids=["fenced-python", "fenced-plain", "tilde-fence"],
    )
    def test_code_block_detection(self, text: str, expected_format: str):
        result = detect_content_format(text)
        assert expected_format in result

    @pytest.mark.parametrize(
        "text, expected_format",
        [
            ("```mermaid\ngraph TD\nA-->B\n```\n", "data_block"),
            ("```yaml\nkey: value\n```\n", "data_block"),
            ("```json\n{}\n```\n", "data_block"),
            ("```toml\n[section]\n```\n", "data_block"),
            ("```xml\n<root/>\n```\n", "data_block"),
            ("```csv\na,b\n1,2\n```\n", "data_block"),
            ("```yml\nfoo: bar\n```\n", "data_block"),
        ],
        ids=["mermaid", "yaml", "json", "toml", "xml", "csv", "yml"],
    )
    def test_data_block_detection(self, text: str, expected_format: str):
        result = detect_content_format(text)
        assert expected_format in result
        assert "code_block" not in result  # data_block, not code_block

    def test_table_detection(self):
        text = "| Col A | Col B |\n| --- | --- |\n| 1 | 2 |\n"
        result = detect_content_format(text)
        assert "table" in result

    def test_table_needs_separator_row(self):
        """A single pipe line without separator is not a table."""
        text = "| not a table |\nsome other line\n"
        result = detect_content_format(text)
        assert "table" not in result

    @pytest.mark.parametrize(
        "text",
        [
            "- item one\n- item two\n",
            "* star item\n",
            "+ plus item\n",
            "  - indented item\n",
        ],
        ids=["dash", "star", "plus", "indented"],
    )
    def test_unordered_list_detection(self, text: str):
        result = detect_content_format(text)
        assert "list" in result

    def test_ordered_list_detection(self):
        text = "1. First step\n2. Second step\n"
        result = detect_content_format(text)
        assert "list" in result

    def test_prose_detection(self):
        text = "This is a paragraph of natural language that is long enough.\n"
        result = detect_content_format(text)
        assert "prose" in result

    def test_prose_requires_nontrivial_length(self):
        """Lines <= 10 chars don't count as prose."""
        text = "short\n"
        result = detect_content_format(text)
        assert "prose" not in result

    def test_prose_ignores_special_line_starts(self):
        """Lines starting with #, |, -, etc. are not prose."""
        text = "# heading\n- list\n| table |\n"
        result = detect_content_format(text)
        assert "prose" not in result

    # ── Frontmatter stripping ─────────────────────────────────────────

    def test_frontmatter_stripped_before_analysis(self):
        """Frontmatter YAML should not count as any content format."""
        text = "---\ntitle: Test\ndescription: A long description field here\n---\n"
        result = detect_content_format(text)
        assert result == []

    def test_frontmatter_stripped_content_after(self):
        text = "---\nid: test\n---\n\n# Real Content\n\nA paragraph of real text here.\n"
        result = detect_content_format(text)
        assert "heading" in result
        assert "prose" in result

    # ── Empty / edge cases ────────────────────────────────────────────

    def test_empty_string(self):
        assert detect_content_format("") == []

    def test_whitespace_only(self):
        assert detect_content_format("   \n\n  \n") == []

    # ── Mixed content ─────────────────────────────────────────────────

    def test_mixed_content_detects_all_formats(self):
        text = (
            "# Architecture\n\n"
            "The system has three components that work together.\n\n"
            "```python\ndef main(): pass\n```\n\n"
            "```mermaid\ngraph TD\nA-->B\n```\n\n"
            "| Name | Type |\n| --- | --- |\n| foo | int |\n\n"
            "- item one\n- item two\n"
        )
        result = detect_content_format(text)
        assert set(result) == {"heading", "prose", "code_block", "data_block", "table", "list"}

    def test_result_is_sorted(self):
        text = "# Heading\n\nProse text that is long enough.\n- list item\n"
        result = detect_content_format(text)
        assert result == sorted(result)

    # ── Code-block-aware detection ────────────────────────────────────

    def test_table_inside_code_block_not_detected(self):
        """Tables inside fenced code blocks are examples, not real tables."""
        text = (
            "Some explanation text for the reader.\n\n```markdown\n| Col A | Col B |\n| --- | --- |\n| 1 | 2 |\n```\n"
        )
        result = detect_content_format(text)
        assert "table" not in result
        assert "code_block" in result

    def test_list_inside_code_block_not_detected(self):
        """Lists inside fenced code blocks are examples, not real lists."""
        text = "Here is how to format a list:\n\n```markdown\n- item one\n- item two\n```\n"
        result = detect_content_format(text)
        assert "list" not in result
        assert "code_block" in result

    def test_prose_inside_code_block_not_detected(self):
        """Long lines inside code blocks are code, not prose."""
        text = "```python\ndef this_is_a_very_long_function_name_not_prose():\n    pass\n```\n"
        result = detect_content_format(text)
        assert "prose" not in result
        assert "code_block" in result

    def test_content_outside_code_block_still_detected(self):
        """Content before/after code blocks should still be detected."""
        text = "# Title\n\nReal prose outside the code block.\n\n```python\ndef main(): pass\n```\n\n- real list item\n"
        result = detect_content_format(text)
        assert "heading" in result
        assert "prose" in result
        assert "list" in result
        assert "code_block" in result

    # ── New inline/block modes ────────────────────────────────────────

    def test_blockquote_detection(self):
        text = "> This is a blockquote\n> with multiple lines\n"
        result = detect_content_format(text)
        assert "blockquote" in result

    def test_bold_detection(self):
        text = "This has **bold text** in it for emphasis.\n"
        result = detect_content_format(text)
        assert "bold" in result

    def test_bold_inside_code_block_not_detected(self):
        text = "```\n**not bold** because inside code\n```\n"
        result = detect_content_format(text)
        assert "bold" not in result

    def test_inline_code_detection(self):
        text = "Use `some_function()` to call it properly.\n"
        result = detect_content_format(text)
        assert "inline_code" in result

    def test_inline_code_inside_code_block_not_detected(self):
        text = "```python\nx = `not inline code`\n```\n"
        result = detect_content_format(text)
        assert "inline_code" not in result

    def test_link_detection(self):
        text = "See [the docs](https://example.com) for details.\n"
        result = detect_content_format(text)
        assert "link" in result

    def test_link_ref_detection(self):
        text = "See [the docs][1] for more information here.\n"
        result = detect_content_format(text)
        assert "link" in result

    def test_link_inside_code_block_not_detected(self):
        text = "```\n[not a link](https://example.com)\n```\n"
        result = detect_content_format(text)
        assert "link" not in result


# ═══════════════════════════════════════════════════════════════════════
# classify_files — content_format auto-detection for freeform files
# ═══════════════════════════════════════════════════════════════════════


class TestClassifyFilesContentFormat:
    """Tests for content_format auto-detection in classify_files()."""

    def _freeform_type(self) -> FileTypeDeclaration:
        return FileTypeDeclaration(
            name="main",
            patterns=("CLAUDE.md",),
            properties={"format": "freeform", "scope": "project"},
        )

    def _schema_type(self) -> FileTypeDeclaration:
        return FileTypeDeclaration(
            name="config",
            patterns=("settings.json",),
            properties={"format": "schema"},
        )

    def test_freeform_gets_content_format(self, tmp_path: Path):
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nSome real paragraph content here.\n")
        result = classify_files(tmp_path, [md], [self._freeform_type()])
        assert len(result) == 1
        cf = result[0].properties.get("content_format")
        assert isinstance(cf, list)
        assert "heading" in cf
        assert "prose" in cf

    def test_schema_format_skips_content_format(self, tmp_path: Path):
        f = tmp_path / "settings.json"
        f.write_text('{"key": "value"}\n')
        result = classify_files(tmp_path, [f], [self._schema_type()])
        assert len(result) == 1
        assert "content_format" not in result[0].properties

    def test_freeform_empty_file_no_content_format(self, tmp_path: Path):
        md = tmp_path / "CLAUDE.md"
        md.write_text("")
        result = classify_files(tmp_path, [md], [self._freeform_type()])
        assert len(result) == 1
        assert "content_format" not in result[0].properties

    def test_explicit_content_format_not_overwritten(self, tmp_path: Path):
        """If content_format is already set in properties, don't overwrite."""
        ft = FileTypeDeclaration(
            name="main",
            patterns=("CLAUDE.md",),
            properties={"format": "freeform", "content_format": ["prose"]},
        )
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Heading\n\n```python\ncode\n```\n")
        result = classify_files(tmp_path, [md], [ft])
        assert result[0].properties["content_format"] == ["prose"]

    def test_freeform_list_format(self, tmp_path: Path):
        """format: [freeform, ...] should also trigger detection."""
        ft = FileTypeDeclaration(
            name="main",
            patterns=("CLAUDE.md",),
            properties={"format": ["freeform", "frontmatter"]},
        )
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nLong enough prose content here.\n")
        result = classify_files(tmp_path, [md], [ft])
        assert "content_format" in result[0].properties


# ═══════════════════════════════════════════════════════════════════════
# match_files — content_format property matching
# ═══════════════════════════════════════════════════════════════════════


class TestMatchFilesContentFormat:
    """Tests for content_format matching in _file_matches / match_files."""

    def _cf(self, content_format: list[str]) -> ClassifiedFile:
        return ClassifiedFile(
            path=Path("/fake/CLAUDE.md"),
            file_type="main",
            properties={"format": "freeform", "content_format": content_format},
        )

    def test_content_format_wildcard(self):
        """content_format=None matches everything."""
        files = [self._cf(["prose", "heading"])]
        result = match_files(files, FileMatch(type="main"))
        assert len(result) == 1

    def test_content_format_match_overlap(self):
        """Rule targets code_block, file has code_block among others."""
        files = [self._cf(["code_block", "heading", "prose"])]
        result = match_files(files, FileMatch(type="main", content_format=["code_block"]))
        assert len(result) == 1

    def test_content_format_no_overlap(self):
        """Rule targets data_block, file only has prose + heading."""
        files = [self._cf(["heading", "prose"])]
        result = match_files(files, FileMatch(type="main", content_format=["data_block"]))
        assert len(result) == 0

    def test_content_format_multi_match(self):
        """Rule targets multiple formats, file has one of them."""
        files = [self._cf(["prose", "list"])]
        result = match_files(
            files,
            FileMatch(type="main", content_format=["code_block", "list"]),
        )
        assert len(result) == 1

    def test_file_without_content_format_no_match(self):
        """File with no content_format property doesn't match explicit criteria."""
        files = [
            ClassifiedFile(
                path=Path("/fake/config.json"),
                file_type="config",
                properties={"format": "schema"},
            )
        ]
        result = match_files(files, FileMatch(type="config", content_format=["prose"]))
        assert len(result) == 0
