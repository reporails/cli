"""A file's leading frontmatter block has one owner: where it is, what it holds, and why it does not read."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.mechanical.checks import frontmatter_key
from reporails_cli.core.lint.mechanical.checks_advanced import (
    frontmatter_extra_keys,
    frontmatter_matches_dirname,
    frontmatter_present,
    frontmatter_valid_glob,
    frontmatter_valid_yaml,
)
from reporails_cli.core.lint.memory_checks import _check_frontmatter
from reporails_cli.core.platform.dto.models import ClassifiedFile
from reporails_cli.core.platform.utils.utils import (
    frontmatter_block,
    read_frontmatter,
    strip_frontmatter,
)


def _cf(root: Path, rel: str) -> list[ClassifiedFile]:
    return [ClassifiedFile(path=root / rel, file_type="rule")]


def _write(root: Path, rel: str, text: str) -> list[ClassifiedFile]:
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text(text, encoding="utf-8")
    return _cf(root, rel)


# -- where the block is -------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_block_is_between_two_whole_delimiter_lines() -> None:
    block = frontmatter_block("---\nname: a\nkind: b\n---\nbody\n")
    assert block is not None
    assert (block.text, block.first_line, block.body_line) == ("name: a\nkind: b", 2, 4)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_longer_dash_run_does_not_close_the_block() -> None:
    block = frontmatter_block("---\nname: a\n----\nmore: b\n---\nbody\n")
    assert block is not None
    assert block.text == "name: a\n----\nmore: b"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_dashes_inside_a_value_do_not_close_the_block() -> None:
    block = frontmatter_block("---\nname: a---b\nkind: c\n---\nbody\n")
    assert block is not None
    assert block.text == "name: a---b\nkind: c"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_block_that_is_never_closed_is_not_a_block() -> None:
    assert frontmatter_block("---\nname: a\nbody\n") is None
    assert frontmatter_block("# Title\n---\nname: a\n---\n") is None


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_first_line_that_is_a_yaml_comment_is_still_the_block() -> None:
    block = frontmatter_block("---\n# a note\nname: a\n---\nbody\n")
    assert block is not None
    assert read_frontmatter("---\n# a note\nname: a\n---\nbody\n").data == {"name": "a"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_delimiters_tolerate_trailing_whitespace_and_crlf() -> None:
    read = read_frontmatter("---  \r\nname: a\r\n---\r\nbody\r\n")
    assert read.data == {"name": "a"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_strip_frontmatter_drops_the_block_or_blanks_its_lines() -> None:
    content = "---\nname: a\n---\nbody\n"
    assert strip_frontmatter(content) == "body\n"
    assert strip_frontmatter(content, keep_lines=True) == "\n\n\nbody\n"
    assert strip_frontmatter("no block\n") == "no block\n"


# -- what it holds ------------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_problem_names_the_file_line_of_the_error() -> None:
    read = read_frontmatter("---\nname: ok\ndescription: [unclosed\n---\nbody\n")
    assert read.data is None
    assert read.problem is not None
    assert read.problem.line == 3
    assert "line 3" in read.problem.message and "\n" not in read.problem.message


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_lenient_reads_a_block_once_its_values_are_quoted() -> None:
    content = "---\ndescription: use: colons\npaths: **/*.ts\n---\nbody\n"
    assert read_frontmatter(content).problem is not None
    lenient = read_frontmatter(content, lenient=True)
    assert lenient.problem is None
    assert lenient.data == {"description": "use: colons", "paths": "**/*.ts"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_block_that_is_not_a_mapping_is_a_problem_and_an_empty_one_is_not() -> None:
    assert read_frontmatter("---\n- a\n- b\n---\n").problem is not None
    empty = read_frontmatter("---\n---\nbody\n")
    assert empty.block is not None and empty.data is None and empty.problem is None


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_missing_block_has_no_data_and_no_problem() -> None:
    read = read_frontmatter("# no block\n")
    assert (read.block, read.data, read.problem) == (None, None, None)
    assert read_frontmatter("---\nid: A\n---").data == {"id": "A"}


# -- the checks read through it -----------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_one_broken_block_is_reported_by_valid_yaml_alone(tmp_path: Path) -> None:
    files = _write(tmp_path, ".claude/rules/ts.md", "---\npaths: [unclosed\n---\nbody\n")
    assert not frontmatter_valid_yaml(tmp_path, {}, files).passed
    assert frontmatter_key(tmp_path, {"key": "paths"}, files).passed
    assert frontmatter_extra_keys(tmp_path, {"allowed": ["paths"]}, files).passed
    assert frontmatter_matches_dirname(tmp_path, {"field": "name"}, files).passed
    assert frontmatter_valid_glob(tmp_path, {"path": ".claude/rules"}, files).passed
    assert frontmatter_present(tmp_path, {}, files).passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_an_unquoted_glob_is_read_the_way_the_agent_reads_it(tmp_path: Path) -> None:
    files = _write(tmp_path, ".claude/rules/ts.md", "---\npaths: **/*.ts\n---\nbody\n")
    assert not frontmatter_valid_yaml(tmp_path, {}, files).passed
    assert frontmatter_valid_yaml(tmp_path, {"lenient": True}, files).passed
    strict = frontmatter_extra_keys(tmp_path, {"allowed": ["paths"], "lenient": True}, files)
    assert strict.passed
    other = _write(tmp_path, ".claude/rules/other.md", "---\npaths: **/*.ts\ntitle: x\n---\nbody\n")
    flagged = frontmatter_extra_keys(tmp_path, {"allowed": ["paths"], "lenient": True}, other)
    assert not flagged.passed and "title" in flagged.message
    assert frontmatter_key(tmp_path, {"key": "paths", "lenient": True}, files).passed
    missing = _write(tmp_path, ".claude/rules/none.md", "---\ntitle: **x\n---\nbody\n")
    assert not frontmatter_key(tmp_path, {"key": "paths", "lenient": True}, missing).passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_valid_glob_reads_an_unquoted_glob_with_lenient_and_points_at_its_line(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/rules/ts.md", "---\nname: r\npaths: **/*.nothing\n---\nbody\n")
    args = {"path": ".claude/rules", "require_matches": True, "lenient": True}
    result = frontmatter_valid_glob(tmp_path, args, [])
    assert not result.passed
    assert result.occurrences == [(".claude/rules/ts.md:3", "Path glob `**/*.nothing` matches no file in the project")]
    assert frontmatter_valid_glob(tmp_path, {**args, "lenient": False}, []).passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_block_closed_by_a_longer_dash_run_is_not_closed(tmp_path: Path) -> None:
    files = _write(tmp_path, "a.md", "---\nname: a\n----\nbody\n")
    assert not frontmatter_present(tmp_path, {}, files).passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_yaml_comment_first_line_still_counts_as_frontmatter(tmp_path: Path) -> None:
    files = _write(tmp_path, "a.md", "---\n# note\nname: a\n---\nbody\n")
    assert frontmatter_present(tmp_path, {}, files).passed
    assert frontmatter_key(tmp_path, {"key": "name"}, files).passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_memory_note_reads_through_the_owner() -> None:
    def kinds(content: str) -> str:
        return " ".join(f.message for f in _check_frontmatter("MEMORY.md", 1, "n.md", content))

    assert "no frontmatter" in kinds("body")
    assert "unclosed" in kinds("---\nname: a\nbody")
    assert "not valid YAML" in kinds("---\nname: [a\n---\n")
    assert "missing frontmatter: description, type" in kinds("---\nname: a\n---\n")
    assert kinds("---\nname: a\ndescription: b\ntype: c\n---\n") == ""


# -- path filter of a glob check ----------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_valid_glob_keeps_a_brace_group_whole(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.ts").write_text("x", encoding="utf-8")
    _write(tmp_path, ".claude/rules/ts.md", "---\npaths: src/**/*.{ts,tsx}\n---\nbody\n")
    args = {"path": ".claude/rules", "require_matches": True, "lenient": True}
    assert frontmatter_valid_glob(tmp_path, args, []).passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_valid_glob_reads_only_the_key_the_file_type_declares(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/rules/ts.md", "---\npaths: nomatch/**/*.ts\nglobs: src/**/*.py\n---\nbody\n")
    args = {"path": ".claude/rules", "require_matches": True, "lenient": True}
    result = frontmatter_valid_glob(tmp_path, args, [])
    assert not result.passed
    assert result.occurrences == [
        (".claude/rules/ts.md:2", "Path glob `nomatch/**/*.ts` matches no file in the project")
    ]


# -- byte-order mark, bytes that are not UTF-8, an unclosed block --------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_leading_byte_order_mark_is_not_part_of_the_first_line() -> None:
    content = "﻿---\nname: a\n---\nbody\n"
    block = frontmatter_block(content)
    assert block is not None and block.text == "name: a"
    assert read_frontmatter(content).data == {"name": "a"}
    assert strip_frontmatter(content) == "body\n"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_block_that_never_closes_is_a_problem_on_line_one() -> None:
    read = read_frontmatter("---\nname: a\nbody\n")
    assert read.block is None and read.problem is not None
    assert (read.problem.line, read.problem.message) == (1, "the frontmatter block is not closed")
    assert read_frontmatter("just text\n").problem is None


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_valid_yaml_reports_an_unclosed_block_once(tmp_path: Path) -> None:
    files = _write(tmp_path, ".claude/skills/s/SKILL.md", "---\nname: s\ndescription: d\n")
    result = frontmatter_valid_yaml(tmp_path, {}, files)
    assert not result.passed
    assert result.occurrences == [
        (".claude/skills/s/SKILL.md:1", "Frontmatter is not valid YAML: the frontmatter block is not closed")
    ]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_file_that_is_not_utf8_raises_nothing(tmp_path: Path) -> None:
    from reporails_cli.core.lint.mechanical.checks import line_count
    from reporails_cli.core.lint.mechanical.checks_advanced import extract_imports

    (tmp_path / ".claude/rules").mkdir(parents=True)
    (tmp_path / ".claude/rules/l.md").write_bytes(b"---\npaths: src/**\n---\ncaf\xe9 @docs/x.md\n")
    files = _cf(tmp_path, ".claude/rules/l.md")
    frontmatter_valid_glob(tmp_path, {"path": ".claude/rules", "require_matches": True}, [])
    assert line_count(tmp_path, {"max": 100}, files).passed
    assert extract_imports(tmp_path, {}, files).passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_block_that_is_not_a_mapping_is_not_also_a_missing_key(tmp_path: Path) -> None:
    files = _write(tmp_path, ".claude/skills/s/SKILL.md", "---\n- a\n- b\n---\nbody\n")
    assert not frontmatter_valid_yaml(tmp_path, {}, files).passed
    assert frontmatter_key(tmp_path, {"key": "description"}, files).passed
    blank = _write(tmp_path, ".claude/skills/t/SKILL.md", "---\nname: t\ndescription:\n---\nbody\n")
    assert not frontmatter_key(tmp_path, {"key": "description"}, blank).passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_the_mapper_strips_a_block_that_follows_a_byte_order_mark() -> None:
    from reporails_cli.core.mapper.markdown_extract import _strip_frontmatter

    stripped, removed = _strip_frontmatter("﻿---\nname: a\n---\n# T\n")
    assert removed == 3 and "name: a" not in stripped


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_form_feed_in_a_value_does_not_break_the_lenient_retry() -> None:
    fm = read_frontmatter("---\npaths: **/*.ts\ndescription: TypeScript\x0crules\n---\nbody\n", lenient=True)
    assert fm.problem is None
    assert fm.data == {"paths": "**/*.ts", "description": "TypeScript\x0crules"}


_DEAD_GLOB_ARGS = {"path": ".claude/rules", "require_matches": True}


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("rule_check", ["valid_markdown", "import_depth", "content_absent", "metadata"])
def test_mechanical_checks_read_a_file_that_is_not_utf8(tmp_path: Path, rule_check: str) -> None:
    from reporails_cli.core.lint.mechanical.checks_advanced import content_absent, import_depth, valid_markdown

    (tmp_path / "CLAUDE.md").write_bytes(b"# Title\n\nNever use rm -rf on caf\xe9 files.\n")
    cfs = [ClassifiedFile(path=tmp_path / "CLAUDE.md", file_type="main")]
    if rule_check == "valid_markdown":
        assert valid_markdown(tmp_path, {}, cfs).passed
    elif rule_check == "import_depth":
        assert import_depth(tmp_path, {"max": 5}, cfs).passed
    elif rule_check == "content_absent":
        assert content_absent(tmp_path, {"pattern": "zzz"}, cfs).passed
    else:
        from reporails_cli.core.lint.mechanical.checks_advanced import _metadata_bytes

        assert _metadata_bytes(tmp_path / "CLAUDE.md") == 0


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_path_filter_with_a_leading_slash_is_read_from_the_project_root(tmp_path: Path) -> None:
    _write(tmp_path, "src/a/b.py", "x = 1\n")
    _write(tmp_path, ".claude/rules/py.md", '---\npaths:\n  - "/src/**/*.py"\n  - "/lib/**/*.py"\n---\nbody\n')
    result = frontmatter_valid_glob(tmp_path, _DEAD_GLOB_ARGS, [])
    assert [msg for _, msg in result.occurrences] == ["Path glob `/lib/**/*.py` matches no file in the project"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_path_filter_matched_only_inside_an_excluded_folder_matches_nothing(tmp_path: Path) -> None:
    _write(tmp_path, "node_modules/x/c.tsx", "x\n")
    _write(tmp_path, ".claude/rules/ts.md", '---\npaths: ["**/*.tsx"]\n---\nbody\n')
    result = frontmatter_valid_glob(tmp_path, _DEAD_GLOB_ARGS, [])
    assert not result.passed
    assert [msg for _, msg in result.occurrences] == ["Path glob `**/*.tsx` matches no file in the project"]
