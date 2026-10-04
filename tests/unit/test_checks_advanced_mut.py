"""Mutation-closing tests for `core/lint/mechanical/checks_advanced.py`.

Each test pins a verdict, branch, count, or threshold that a specific injected
operator mutation flips, so the assertion reddens the moment that bug returns.
Derived from the mutation probe over `checks_advanced.py`; targets the
frontmatter / glob / markdown-link / directory checks the existing suite left
without direct coverage.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.mechanical.checks_advanced import (
    _is_external_link,
    _metadata_bytes,
    check_markdown_link_targets_exist,
    directory_file_types,
    extract_imports,
    extract_markdown_links,
    frontmatter_extra_keys,
    frontmatter_present,
    frontmatter_valid_glob,
    frontmatter_valid_yaml,
    import_depth,
    path_resolves,
    valid_markdown,
)
from reporails_cli.core.platform.dto.models import ClassifiedFile


def _cf(root: Path, *rels: str, ft: str = "main") -> list[ClassifiedFile]:
    return [ClassifiedFile(path=root / p, file_type=ft) for p in rels]


# ── frontmatter_present ───────────────────────────────────────────────


class TestFrontmatterPresent:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_frontmatter_found_passes(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("---\nname: x\n---\nbody\n")
        result = frontmatter_present(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert result.passed  # kills L40 passed=True -> False

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_frontmatter_fails(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("# no frontmatter here\n")
        result = frontmatter_present(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert not result.passed  # kills L43 passed=False -> True


# ── frontmatter_valid_yaml ────────────────────────────────────────────


class TestFrontmatterValidYaml:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_sequence_frontmatter_is_not_mapping(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("---\n- a\n- b\n---\nbody\n")
        result = frontmatter_valid_yaml(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert not result.passed
        assert result.occurrences == [("a.md:2", "Frontmatter is not valid YAML: the block is not a YAML mapping")]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_invalid_yaml_frontmatter_fails_at_the_line_of_the_problem(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("---\nname: x\nfoo: [bar\n---\nbody\n")
        result = frontmatter_valid_yaml(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert not result.passed
        ((location, message),) = result.occurrences or []
        assert location == "a.md:3"
        assert message.startswith("Frontmatter is not valid YAML:") and "(line 3)" in message

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_each_broken_file_is_its_own_occurrence(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("---\nfoo: [bar\n---\n")
        (tmp_path / "b.md").write_text("---\nfoo: ok\n---\n")
        (tmp_path / "c.md").write_text("---\nbar: [baz\n---\n")
        files = _cf(tmp_path, "a.md") + _cf(tmp_path, "b.md") + _cf(tmp_path, "c.md")
        result = frontmatter_valid_yaml(tmp_path, {}, files)
        assert [loc.split(":")[0] for loc, _ in result.occurrences or []] == ["a.md", "c.md"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_lenient_reads_unquoted_values_a_strict_read_refuses(self, tmp_path: Path) -> None:
        (tmp_path / "r.md").write_text("---\ndescription: use: colons\npaths: **/*.ts\n---\nbody\n")
        files = _cf(tmp_path, "r.md")
        assert not frontmatter_valid_yaml(tmp_path, {}, files).passed
        assert frontmatter_valid_yaml(tmp_path, {"lenient": True}, files).passed

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_frontmatter_to_validate_passes(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("# just prose, no frontmatter\n")
        result = frontmatter_valid_yaml(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert result.passed


# ── simple verdict pins: valid_markdown / path_resolves / extract_imports ──


class TestSimpleVerdicts:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_broken_heading_fails(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("#Heading missing the space\n")
        result = valid_markdown(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert not result.passed  # kills L105 passed=False -> True
        assert "Broken heading" in result.message

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_broken_heading_line_number_counts_frontmatter(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("---\nname: x\n---\n# Title\n\nText.\n#Oops\n")
        result = valid_markdown(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert result.location == "a.md:7"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_hash_lines_in_code_are_not_broken_headings(self, tmp_path: Path) -> None:
        """A shebang or `#include` line in a fenced or indented code block is code, not a heading."""
        (tmp_path / "a.md").write_text("# Title\n\n```bash\n#!/bin/bash\n#build\n```\n\n    #include <x.h>\n")
        assert valid_markdown(tmp_path, {}, _cf(tmp_path, "a.md")).passed

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_existing_target_passes(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("x")
        result = path_resolves(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert result.passed  # kills L122 passed=True -> False

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_import_found_passes(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("See @docs/guide.md for setup.\n")
        result = extract_imports(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert result.passed  # kills L149 passed=True -> False
        assert result.annotations["discovered_imports"] == ["docs/guide.md"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_inline_code_at_path_not_discovered_as_import(self, tmp_path: Path) -> None:
        """Regression: an `@path`-shaped reference inside an inline code span
        (`` `npx @reporails/cli check .` ``) used to be discovered as a real
        import — `check_import_targets_exist` then flagged it "unresolved" on any
        file documenting a scoped npm package, including our own SKILL.md."""
        (tmp_path / "a.md").write_text("Run `npx @reporails/cli check .` to lint your repo. See @docs/guide.md too.\n")
        result = extract_imports(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert result.passed
        assert result.annotations["discovered_imports"] == ["docs/guide.md"]


# ── _metadata_bytes ───────────────────────────────────────────────────


class TestMetadataBytes:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unterminated_frontmatter_returns_zero(self, tmp_path: Path) -> None:
        # startswith('---') is True but there is NO closing '---'. The `or` short-circuit
        # must return 0; the `and` mutation parses the partial body and returns >0.
        p = tmp_path / "SKILL.md"
        p.write_text("---\nname: x\ndescription: y\n")
        assert _metadata_bytes(p) == 0  # kills L172 or -> and


# ── import_depth ──────────────────────────────────────────────────────


class TestImportDepth:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_import_cycle_terminates(self, tmp_path: Path) -> None:
        # a -> b -> a. The `visited` guard (L228 `in visited or ...`) terminates the
        # walk; the `and` mutation loses it and recurses without bound (probe records
        # CAUGHT via hang/RecursionError). Unmutated: deepest is small, within max.
        (tmp_path / "a.md").write_text("@b.md\n")
        (tmp_path / "b.md").write_text("@a.md\n")
        result = import_depth(tmp_path, {"max": 5}, _cf(tmp_path, "a.md"))
        assert result.passed  # kills L228 or -> and

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_imports_within_limit_passes(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("# no imports at all\n")
        result = import_depth(tmp_path, {"max": 5}, _cf(tmp_path, "a.md"))
        assert result.passed  # kills L253 passed=True -> False


# ── directory_file_types ──────────────────────────────────────────────


class TestDirectoryFileTypes:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_all_allowed_extensions_passes(self, tmp_path: Path) -> None:
        d = tmp_path / "d"
        d.mkdir()
        (d / "a.md").write_text("x")
        result = directory_file_types(tmp_path, {"path": "d", "extensions": [".md"]}, [])
        # A file with an allowed suffix must NOT be flagged: original `is_file() and
        # suffix not in ext` yields False (not bad); the `or` mutation flags every file.
        assert result.passed  # kills L267 and -> or, and L270 passed=True -> False

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_disallowed_extension_fails(self, tmp_path: Path) -> None:
        d = tmp_path / "d"
        d.mkdir()
        (d / "a.txt").write_text("x")
        result = directory_file_types(tmp_path, {"path": "d", "extensions": [".md"]}, [])
        assert not result.passed


# ── frontmatter_valid_glob ────────────────────────────────────────────


class TestFrontmatterValidGlob:
    def _write_glob_md(self, d: Path, name: str, key: str, values: list[str]) -> None:
        lines = "\n".join(f"  - '{v}'" for v in values)
        (d / name).write_text(f"---\n{key}:\n{lines}\n---\nbody\n")

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_dir_not_found_passes(self, tmp_path: Path) -> None:
        result = frontmatter_valid_glob(tmp_path, {"path": "nonexistent"}, [])
        assert result.passed  # kills L318 passed=True -> False

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unbalanced_brackets_fails(self, tmp_path: Path) -> None:
        d = tmp_path / "d"
        d.mkdir()
        self._write_glob_md(d, "r.md", "globs", ["foo["])
        result = frontmatter_valid_glob(tmp_path, {"path": "d"}, [])
        assert not result.passed  # kills L354 != -> == (1 == 0 would skip the flag)
        assert "unbalanced" in result.message

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_non_md_file_is_skipped(self, tmp_path: Path) -> None:
        d = tmp_path / "d"
        d.mkdir()
        # A .txt file with an invalid glob must be skipped (only .md is processed);
        # the `==` mutation on the suffix guard would process the .txt and fail.
        self._write_glob_md(d, "r.txt", "globs", ["foo["])
        result = frontmatter_valid_glob(tmp_path, {"path": "d"}, [])
        assert result.passed  # kills L321 != -> ==

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_require_matches_unresolved_fails(self, tmp_path: Path) -> None:
        d = tmp_path / "d"
        d.mkdir()
        self._write_glob_md(d, "r.md", "globs", ["nomatch/*.md"])
        result = frontmatter_valid_glob(tmp_path, {"path": "d", "require_matches": True}, [])
        assert not result.passed  # kills L327 passed=False -> True
        assert "match no files" in result.message

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_an_unmatched_glob_is_reported_on_its_own_file_and_line(self, tmp_path: Path) -> None:
        (tmp_path / "target.md").write_text("x")
        d = tmp_path / "d"
        d.mkdir()
        self._write_glob_md(d, "a.md", "paths", ["target.md"])
        self._write_glob_md(d, "b.md", "paths", ["target.md", "tools/**"])
        result = frontmatter_valid_glob(tmp_path, {"path": "d", "require_matches": True}, [])
        assert result.occurrences == [("d/b.md:4", "Path glob `tools/**` matches no file in the project")]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_an_unmatched_glob_is_located_on_its_own_entry_not_a_longer_one(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.py").write_text("x")
        d = tmp_path / "d"
        d.mkdir()
        (d / "b.md").write_text("---\ndescription: covers lib/**\npaths:\n  - 'lib/**/*.py'\n  - 'lib/**'\n---\nbody\n")
        result = frontmatter_valid_glob(tmp_path, {"path": "d", "require_matches": True}, [])
        assert [loc for loc, _ in result.occurrences] == ["d/b.md:4", "d/b.md:5"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_require_matches_resolved_passes(self, tmp_path: Path) -> None:
        (tmp_path / "target.md").write_text("x")
        d = tmp_path / "d"
        d.mkdir()
        self._write_glob_md(d, "r.md", "globs", ["target.md"])
        result = frontmatter_valid_glob(tmp_path, {"path": "d", "require_matches": True}, [])
        # A matching glob must resolve: original `any(True ...)` is truthy; the
        # `True -> False` mutation makes every glob read as unresolved.
        assert result.passed  # kills L358 True -> False

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_paths_key_fallback_validated(self, tmp_path: Path) -> None:
        d = tmp_path / "d"
        d.mkdir()
        # Only the `paths` key holds the glob (no `globs` key). The chained-`or`
        # fallback must still validate it; an `and` mutation collapses the chain to [].
        self._write_glob_md(d, "r.md", "paths", ["foo["])
        result = frontmatter_valid_glob(tmp_path, {"path": "d"}, [])
        assert not result.passed  # kills L348 or -> and (globs or paths)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_applyto_key_fallback_validated(self, tmp_path: Path) -> None:
        d = tmp_path / "d"
        d.mkdir()
        self._write_glob_md(d, "r.md", "applyTo", ["foo["])
        result = frontmatter_valid_glob(tmp_path, {"path": "d"}, [])
        assert not result.passed  # kills L348 or -> and (paths or applyTo)


# ── markdown links ────────────────────────────────────────────────────


class TestMarkdownLinks:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_is_external_link_mailto(self) -> None:
        # No "://" present — the `or` must still classify mailto as external;
        # the `and` mutation drops it to internal.
        assert _is_external_link("mailto:a@b.com") is True  # kills L458 or -> and

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_external_link_is_not_discovered(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("[x](http://example.com)\n")
        result = extract_markdown_links(tmp_path, {}, _cf(tmp_path, "a.md"))
        # An external link must be filtered out of the discovered set; the `and`
        # mutation on the skip guard would append it.
        assert (result.annotations or {}).get("discovered_markdown_links", []) == []
        assert result.passed  # kills L500 or -> and

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_links_passes(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("# just prose, no links at all\n")
        result = extract_markdown_links(tmp_path, {}, _cf(tmp_path, "a.md"))
        assert result.passed  # kills L513 passed=True -> False
        assert "No markdown links" in result.message

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_broken_link_target_fails(self, tmp_path: Path) -> None:
        (tmp_path / "src.md").write_text("body")
        args = {"discovered_markdown_links": ["src.md::missing.md::1"]}
        result = check_markdown_link_targets_exist(tmp_path, args, [])
        assert not result.passed  # kills L547 passed=False -> True
        assert [loc for loc, _ in result.occurrences or []] == ["src.md:1"]


# ── frontmatter_extra_keys ────────────────────────────────────────────


class TestFrontmatterExtraKeys:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_extra_key_fails(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("---\npaths: x\nfoo: 1\n---\nbody\n")
        result = frontmatter_extra_keys(tmp_path, {"allowed": ["paths"]}, _cf(tmp_path, "a.md"))
        assert not result.passed  # kills L709 passed=False -> True
        assert "foo" in result.message


class TestFrontmatterValidGlobWalk:
    """The rule-file walk skips excluded folders and survives a symlink cycle."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_excluded_folder_is_not_walked(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules"
        (rules / "node_modules").mkdir(parents=True)
        (rules / "node_modules" / "bad.md").write_text("---\nglobs:\n  - 'foo['\n---\nbody\n")
        assert frontmatter_valid_glob(tmp_path, {"path": "rules"}, []).passed

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_project_excluded_folder_is_not_walked(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules"
        (rules / "drafts").mkdir(parents=True)
        (rules / "drafts" / "bad.md").write_text("---\nglobs:\n  - 'foo['\n---\nbody\n")
        (tmp_path / ".ails").mkdir()
        (tmp_path / ".ails" / "config.local.yml").write_text("exclude_dirs:\n  - drafts\n")
        assert frontmatter_valid_glob(tmp_path, {"path": "rules"}, []).passed

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_symlink_cycle_terminates(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules"
        rules.mkdir()
        (rules / "loop").symlink_to(rules, target_is_directory=True)
        (rules / "ok.md").write_text("---\nglobs:\n  - '*.py'\n---\nbody\n")
        assert frontmatter_valid_glob(tmp_path, {"path": "rules"}, []).passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_valid_markdown_ignores_hash_text_inside_list_items_and_quotes(tmp_path: Path) -> None:
    (tmp_path / "a.md").write_text("# T\n\n- #123 tracks the rewrite\n\n> #note keep it\n", encoding="utf-8")
    assert valid_markdown(tmp_path, {}, _cf(tmp_path, "a.md")).passed
    (tmp_path / "b.md").write_text("# T\n\n#broken heading\n", encoding="utf-8")
    assert not valid_markdown(tmp_path, {}, _cf(tmp_path, "b.md")).passed


class TestFrontmatterValidGlobAnchoring:
    """Path globs read from the project root and walk only the folder they name."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unanchored_glob_does_not_match_a_nested_folder(self, tmp_path: Path) -> None:
        (tmp_path / "rules").mkdir()
        (tmp_path / "rules" / "r.md").write_text("---\npaths: src/**/*.ts\n---\nbody\n")
        (tmp_path / "packages" / "web" / "src").mkdir(parents=True)
        (tmp_path / "packages" / "web" / "src" / "a.ts").write_text("x\n")
        result = frontmatter_valid_glob(tmp_path, {"path": "rules", "require_matches": True}, [])
        assert not result.passed

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_double_star_prefix_matches_at_any_depth(self, tmp_path: Path) -> None:
        (tmp_path / "rules").mkdir()
        (tmp_path / "rules" / "r.md").write_text("---\npaths: '**/src/**/*.ts'\n---\nbody\n")
        (tmp_path / "packages" / "web" / "src").mkdir(parents=True)
        (tmp_path / "packages" / "web" / "src" / "a.ts").write_text("x\n")
        assert frontmatter_valid_glob(tmp_path, {"path": "rules", "require_matches": True}, []).passed

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_glob_over_a_symlinked_folder_is_not_dead(self, tmp_path: Path) -> None:
        (tmp_path / ".agents" / "skills" / "foo").mkdir(parents=True)
        (tmp_path / ".agents" / "skills" / "foo" / "SKILL.md").write_text("# foo\n")
        (tmp_path / ".claude" / "rules").mkdir(parents=True)
        (tmp_path / ".claude" / "skills").symlink_to("../.agents/skills", target_is_directory=True)
        (tmp_path / ".claude" / "rules" / "r.md").write_text("---\npaths: .claude/skills/**\n---\nbody\n")
        args = {"path": ".claude/rules", "require_matches": True}
        assert frontmatter_valid_glob(tmp_path, args, []).passed

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_excluded_folder_files_do_not_satisfy_a_glob(self, tmp_path: Path) -> None:
        (tmp_path / "rules").mkdir()
        (tmp_path / "rules" / "r.md").write_text("---\npaths: '**/*.ts'\n---\nbody\n")
        (tmp_path / "node_modules" / "p").mkdir(parents=True)
        (tmp_path / "node_modules" / "p" / "a.ts").write_text("x\n")
        assert not frontmatter_valid_glob(tmp_path, {"path": "rules", "require_matches": True}, []).passed
