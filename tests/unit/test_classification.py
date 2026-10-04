"""Tests for the classification engine — content format detection and file matching."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, detect_content_format
from reporails_cli.core.platform.dto.models import ClassifiedFile, FileMatch, FileTypeDeclaration
from reporails_cli.core.platform.policy.matching import match_files

# ═══════════════════════════════════════════════════════════════════════
# detect_content_format — individual format detection
# ═══════════════════════════════════════════════════════════════════════


class TestDetectContentFormat:
    """Tests for detect_content_format() region detection."""

    @pytest.mark.unit
    @pytest.mark.subsys_classify
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

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_heading_requires_space_after_hash(self):
        """#hashtag is not a heading."""
        result = detect_content_format("#hashtag not a heading\n")
        assert "heading" not in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
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

    @pytest.mark.unit
    @pytest.mark.subsys_classify
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

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_table_detection(self):
        text = "| Col A | Col B |\n| --- | --- |\n| 1 | 2 |\n"
        result = detect_content_format(text)
        assert "table" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_table_needs_separator_row(self):
        """A single pipe line without separator is not a table."""
        text = "| not a table |\nsome other line\n"
        result = detect_content_format(text)
        assert "table" not in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
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

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_ordered_list_detection(self):
        text = "1. First step\n2. Second step\n"
        result = detect_content_format(text)
        assert "list" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_prose_detection(self):
        text = "This is a paragraph of natural language that is long enough.\n"
        result = detect_content_format(text)
        assert "prose" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_prose_requires_nontrivial_length(self):
        """Lines <= 10 chars don't count as prose."""
        text = "short\n"
        result = detect_content_format(text)
        assert "prose" not in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_prose_ignores_special_line_starts(self):
        """Lines starting with #, |, -, etc. are not prose."""
        text = "# heading\n- list\n| table |\n"
        result = detect_content_format(text)
        assert "prose" not in result

    # ── Frontmatter stripping ─────────────────────────────────────────

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_frontmatter_stripped_before_analysis(self):
        """Frontmatter YAML should not count as any content format."""
        text = "---\ntitle: Test\ndescription: A long description field here\n---\n"
        result = detect_content_format(text)
        assert result == []

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_frontmatter_stripped_content_after(self):
        text = "---\nid: test\n---\n\n# Real Content\n\nA paragraph of real text here.\n"
        result = detect_content_format(text)
        assert "heading" in result
        assert "prose" in result

    # ── Empty / edge cases ────────────────────────────────────────────

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_empty_string(self):
        assert detect_content_format("") == []

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_whitespace_only(self):
        assert detect_content_format("   \n\n  \n") == []

    # ── Mixed content ─────────────────────────────────────────────────

    @pytest.mark.unit
    @pytest.mark.subsys_classify
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

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_result_is_sorted(self):
        text = "# Heading\n\nProse text that is long enough.\n- list item\n"
        result = detect_content_format(text)
        assert result == sorted(result)

    # ── Code-block-aware detection ────────────────────────────────────

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_table_inside_code_block_not_detected(self):
        """Tables inside fenced code blocks are examples, not real tables."""
        text = (
            "Some explanation text for the reader.\n\n```markdown\n| Col A | Col B |\n| --- | --- |\n| 1 | 2 |\n```\n"
        )
        result = detect_content_format(text)
        assert "table" not in result
        assert "code_block" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_list_inside_code_block_not_detected(self):
        """Lists inside fenced code blocks are examples, not real lists."""
        text = "Here is how to format a list:\n\n```markdown\n- item one\n- item two\n```\n"
        result = detect_content_format(text)
        assert "list" not in result
        assert "code_block" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_prose_inside_code_block_not_detected(self):
        """Long lines inside code blocks are code, not prose."""
        text = "```python\ndef this_is_a_very_long_function_name_not_prose():\n    pass\n```\n"
        result = detect_content_format(text)
        assert "prose" not in result
        assert "code_block" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_content_outside_code_block_still_detected(self):
        """Content before/after code blocks should still be detected."""
        text = "# Title\n\nReal prose outside the code block.\n\n```python\ndef main(): pass\n```\n\n- real list item\n"
        result = detect_content_format(text)
        assert "heading" in result
        assert "prose" in result
        assert "list" in result
        assert "code_block" in result

    # ── New inline/block modes ────────────────────────────────────────

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_blockquote_detection(self):
        text = "> This is a blockquote\n> with multiple lines\n"
        result = detect_content_format(text)
        assert "blockquote" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_bold_detection(self):
        text = "This has **bold text** in it for emphasis.\n"
        result = detect_content_format(text)
        assert "bold" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_bold_inside_code_block_not_detected(self):
        text = "```\n**not bold** because inside code\n```\n"
        result = detect_content_format(text)
        assert "bold" not in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_inline_code_detection(self):
        text = "Use `some_function()` to call it properly.\n"
        result = detect_content_format(text)
        assert "inline_code" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_inline_code_inside_code_block_not_detected(self):
        text = "```python\nx = `not inline code`\n```\n"
        result = detect_content_format(text)
        assert "inline_code" not in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_link_detection(self):
        text = "See [the docs](https://example.com) for details.\n"
        result = detect_content_format(text)
        assert "link" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_link_ref_detection(self):
        text = "See [the docs][1] for more information here.\n\n[1]: https://example.com\n"
        result = detect_content_format(text)
        assert "link" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_link_ref_without_definition_is_text(self):
        """A `[text][ref]` with no definition is plain text, as the markdown parse reads it."""
        result = detect_content_format("See [the docs][1] for more information here.\n")
        assert "link" not in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_link_shown_in_code_span_not_detected(self):
        result = detect_content_format("Write it as `[Name](url)` in the file.\n")
        assert "link" not in result
        assert "inline_code" in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_indented_fence_in_list_item_is_detected(self):
        """A fence nested in a list item is a code block, and its interior is not a list or heading."""
        text = "- Run it:\n\n  ```yaml\n  - a\n  # not a heading\n  ```\n"
        result = detect_content_format(text)
        assert "data_block" in result
        assert "heading" not in result

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_table_indented_in_list_item_is_detected(self):
        text = "1. Pick:\n\n   | Name | Value |\n   |------|-------|\n   | a | b |\n"
        assert "table" in detect_content_format(text)

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_html_comment_is_not_prose(self):
        text = "<!-- READ THIS FIRST: fill in every field below -->\n"
        assert "prose" not in detect_content_format(text)

    @pytest.mark.unit
    @pytest.mark.subsys_classify
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

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_freeform_gets_content_format(self, tmp_path: Path):
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nSome real paragraph content here.\n")
        result = classify_files(tmp_path, [md], [self._freeform_type()])
        assert len(result) == 1
        cf = result[0].properties.get("content_format")
        assert isinstance(cf, list)
        assert "heading" in cf
        assert "prose" in cf

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_schema_format_skips_content_format(self, tmp_path: Path):
        f = tmp_path / "settings.json"
        f.write_text('{"key": "value"}\n')
        result = classify_files(tmp_path, [f], [self._schema_type()])
        assert len(result) == 1
        assert "content_format" not in result[0].properties

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_freeform_empty_file_no_content_format(self, tmp_path: Path):
        md = tmp_path / "CLAUDE.md"
        md.write_text("")
        result = classify_files(tmp_path, [md], [self._freeform_type()])
        assert len(result) == 1
        assert "content_format" not in result[0].properties

    @pytest.mark.unit
    @pytest.mark.subsys_classify
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

    @pytest.mark.unit
    @pytest.mark.subsys_classify
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
# classify_files — subagent / plugin match-type aliases
# ═══════════════════════════════════════════════════════════════════════


class TestOneFileTypeVocabulary:
    """A classified file's type is its agent config's file-type key, and rules match on that
    key. A rule that reads markdown also names `format: [frontmatter, freeform]`, so an agent
    whose surface of the same type is not markdown (Codex's TOML `agents`, its Starlark
    `rules`) is never checked by it.
    """

    _MARKDOWN = FileMatch(type="agents", format=["frontmatter", "freeform"])

    def _decl(self, name: str, pattern: str, fmt: object) -> FileTypeDeclaration:
        return FileTypeDeclaration(name=name, patterns=(pattern,), properties={"scope": "global", "format": fmt})

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    @pytest.mark.parametrize(
        ("name", "rel", "fmt"),
        [
            ("agents", ".claude/agents/reviewer.md", ["frontmatter", "freeform"]),
            ("plugins", ".claude-plugin/plugin.json", "schema_validated"),
            ("rules", ".claude/rules/style.md", ["frontmatter", "freeform"]),
            ("skills", ".claude/skills/deploy/SKILL.md", ["frontmatter", "freeform"]),
        ],
    )
    def test_the_classified_type_is_the_config_key(self, tmp_path: Path, name: str, rel: str, fmt: object):
        f = tmp_path / rel
        f.parent.mkdir(parents=True)
        f.write_text("---\nname: x\n---\nBody.\n")
        pattern = rel.replace("reviewer.md", "*.md").replace("style.md", "*.md").replace("deploy", "*")
        (cf,) = classify_files(tmp_path, [f], [self._decl(name, pattern, fmt)])
        assert cf.file_type == name

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_a_markdown_rule_selects_markdown_agents_never_toml_agents(self, tmp_path: Path):
        md = tmp_path / ".claude" / "agents" / "reviewer.md"
        toml = tmp_path / ".codex" / "agents" / "reviewer.toml"
        for f, text in ((md, "---\nname: reviewer\n---\nBody.\n"), (toml, 'name = "reviewer"\n')):
            f.parent.mkdir(parents=True)
            f.write_text(text)
        classified = classify_files(
            tmp_path,
            [md, toml],
            [
                self._decl("agents", ".claude/agents/*.md", ["frontmatter", "freeform"]),
                self._decl("agents", ".codex/agents/*.toml", "schema_validated"),
            ],
        )
        assert {cf.file_type for cf in classified} == {"agents"}
        assert [cf.path for cf in match_files(classified, self._MARKDOWN)] == [md]
        assert len(match_files(classified, FileMatch(type="agents"))) == 2

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_a_markdown_rule_never_reaches_starlark_rules(self, tmp_path: Path):
        starlark = tmp_path / ".codex" / "rules" / "default.rules"
        starlark.parent.mkdir(parents=True)
        starlark.write_text('prefix_rule(pattern = ["git", "push"], decision = "prompt")\n')
        classified = classify_files(
            tmp_path, [starlark], [self._decl("rules", ".codex/rules/*.rules", "schema_validated")]
        )
        assert [cf.file_type for cf in classified] == ["rules"]
        assert match_files(classified, FileMatch(type="rules", format=["frontmatter", "freeform"])) == []


class TestClassifyFilesFileScanRoot:
    """Regression: a file passed as scan_root must classify like its parent dir.

    `ails check ./CLAUDE.md` routes the file path down as scan_root. Before
    the normalization fix, `file_path.relative_to(scan_root)` raised on the
    file-equals-scan_root case, the absolute-path fallback never matched the
    `**/CLAUDE.md` glob, and the file got no file_type — so a single-file
    scan returned zero findings.
    """

    def _main_type(self) -> FileTypeDeclaration:
        return FileTypeDeclaration(
            name="main",
            patterns=("**/CLAUDE.md",),
            properties={"format": "freeform", "scope": "project"},
        )

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_file_scan_root_classifies_same_as_dir(self, tmp_path: Path):
        md = tmp_path / "CLAUDE.md"
        md.write_text("# Title\n\nSome real paragraph content here.\n")
        ft = self._main_type()

        file_root = classify_files(md, [md], [ft])
        dir_root = classify_files(tmp_path, [md], [ft])

        assert [c.file_type for c in file_root] == ["main"]
        assert [c.file_type for c in file_root] == [c.file_type for c in dir_root]


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

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_content_format_wildcard(self):
        """content_format=None matches everything."""
        files = [self._cf(["prose", "heading"])]
        result = match_files(files, FileMatch(type="main"))
        assert len(result) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_content_format_match_overlap(self):
        """Rule targets code_block, file has code_block among others."""
        files = [self._cf(["code_block", "heading", "prose"])]
        result = match_files(files, FileMatch(type="main", content_format=["code_block"]))
        assert len(result) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_content_format_no_overlap(self):
        """Rule targets data_block, file only has prose + heading."""
        files = [self._cf(["heading", "prose"])]
        result = match_files(files, FileMatch(type="main", content_format=["data_block"]))
        assert len(result) == 0

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_content_format_multi_match(self):
        """Rule targets multiple formats, file has one of them."""
        files = [self._cf(["prose", "list"])]
        result = match_files(
            files,
            FileMatch(type="main", content_format=["code_block", "list"]),
        )
        assert len(result) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_classify
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


# ═══════════════════════════════════════════════════════════════════════
# match_files — loading_verb / link_source_type property matching
# (these two MATCH_PROPERTIES were hard-wired
# to None by the rule builder, so a rule targeting them silently matched
# everything, or nothing, depending on which side of the test you asked.)
# ═══════════════════════════════════════════════════════════════════════


class TestMatchFilesLoadingVerbAndLinkSourceType:
    """`loading_verb` / `link_source_type` are the edge-attribution properties
    `core/classify/generic_type.py::make_generic_classified` sets on a link-reached file
    (`generic` / `referenced`). A rule declaring `match: {loading_verb: ...}` must build a
    `FileMatch` that actually carries the value (through `build_rule` -> `_parse_match`, the
    real frontmatter-to-FileMatch path a rule.md goes through) AND `match_files` must then
    filter files by it end to end. Before the fix, `_parse_match` dropped both properties, so
    `rule.match.loading_verb` was always `None` and every file "matched" (a wildcard), no
    matter what the rule author wrote."""

    def _generic(self, *, loading_verb: list[str], link_source_type: list[str]) -> ClassifiedFile:
        return ClassifiedFile(
            path=Path("/fake/docs/arch.md"),
            file_type="generic",
            properties={
                "format": "freeform",
                "loading_verb": loading_verb,
                "link_source_type": link_source_type,
            },
        )

    def _rule_match(self, match_frontmatter: dict[str, object]) -> FileMatch:
        from reporails_cli.core.platform.adapters.registry import build_rule

        frontmatter = {
            "id": "CORE:S:0999",
            "title": "Probe",
            "category": "structure",
            "type": "deterministic",
            "slug": "probe",
            "match": match_frontmatter,
        }
        rule = build_rule(frontmatter, Path("test.md"), None)
        assert rule.match is not None
        return rule.match

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_loading_verb_from_rule_frontmatter_matches_overlap(self):
        match = self._rule_match({"type": "generic", "loading_verb": ["imported"]})
        files = [self._generic(loading_verb=["imported"], link_source_type=["main"])]
        assert len(match_files(files, match)) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_loading_verb_from_rule_frontmatter_excludes_no_overlap(self):
        match = self._rule_match({"type": "generic", "loading_verb": ["imported"]})
        files = [self._generic(loading_verb=["read"], link_source_type=["main"])]
        assert len(match_files(files, match)) == 0

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_link_source_type_from_rule_frontmatter_matches_overlap(self):
        match = self._rule_match({"type": "generic", "link_source_type": ["skills"]})
        files = [self._generic(loading_verb=["read"], link_source_type=["skills"])]
        assert len(match_files(files, match)) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_link_source_type_from_rule_frontmatter_excludes_no_overlap(self):
        match = self._rule_match({"type": "generic", "link_source_type": ["skills"]})
        files = [self._generic(loading_verb=["read"], link_source_type=["main"])]
        assert len(match_files(files, match)) == 0
