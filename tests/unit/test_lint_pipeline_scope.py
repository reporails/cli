"""Unit tests for the 0.5.10 lint-pipeline scope correctness fixes.

Covers:
- `_strip_code_spans` in `core/lint/mechanical/checks_advanced.py` and the
  mirror in `core/classify/link_walker.py` — `[text](path)` inside backticks
  must not surface as a real link.
- `_resolve_glob_targets` in `core/lint/mechanical/checks.py` — `args.path`
  globs must honor `.ails/config.yml: exclude_dirs`.
- `_relativize` in `core/lint/mechanical/runner.py` — paths under root
  serialize as project-relative; anything else falls back to basename.
- `_classified_display` in `core/lint/mechanical/runner.py` — files the
  classifier marked `precedence: user` serialize with a `~/<rel>` prefix
  when rooted under the user's home; classifier output is the source of
  truth, not path-prefix heuristics.
- `_first_classified_path` in `core/lint/mechanical/runner.py` — must skip
  user-scope and managed-scope files so project-wide findings don't
  misattribute to `~/.claude/CLAUDE.md`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify.link_walker import (
    _strip_code_spans as link_walker_strip,
)
from reporails_cli.core.lint.mechanical.checks import (
    _exclude_cache,
    _get_target_files,
    _glob_cache,
    _resolve_glob_targets,
)
from reporails_cli.core.lint.mechanical.checks_advanced import (
    _strip_code_spans as checks_advanced_strip,
)
from reporails_cli.core.lint.mechanical.checks_advanced import (
    extract_markdown_links,
)
from reporails_cli.core.lint.mechanical.runner import (
    _classified_display,
    _first_classified_path,
    _relativize,
)
from reporails_cli.core.platform.dto.models import ClassifiedFile

# ── _strip_code_spans ─────────────────────────────────────────────────


class TestStripCodeSpans:
    """Both extractors strip code spans so `[x](y)` inside backticks isn't a link."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_inline_code_removed(self) -> None:
        text = "Outside `[skip](this)` outside."
        out = checks_advanced_strip(text)
        assert "[skip](this)" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_fenced_code_removed(self) -> None:
        text = "Before\n```\n[skip](inside.md)\n```\nAfter"
        out = checks_advanced_strip(text)
        assert "[skip](inside.md)" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_plain_link_preserved(self) -> None:
        text = "See [real](target.md) for details."
        out = checks_advanced_strip(text)
        assert "[real](target.md)" in out

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_link_walker_mirror_behaves_identically(self) -> None:
        text = "Outside `[skip](this)` and a real [keep](here.md)."
        a = checks_advanced_strip(text)
        b = link_walker_strip(text)
        assert a == b

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_extract_markdown_links_skips_code_spans(self, tmp_path: Path) -> None:
        # End-to-end: extractor must not annotate links found inside code spans.
        f = tmp_path / "README.md"
        f.write_text("Describes link syntax: `[text](path)` is documentation.\n\nReal link: [target](exists.md)\n")
        (tmp_path / "exists.md").write_text("# placeholder\n")
        cf = ClassifiedFile(path=f, file_type="main", properties={})
        result = extract_markdown_links(tmp_path, {"path": "**/*.md"}, [cf])
        assert result.passed
        ann = (result.annotations or {}).get("discovered_markdown_links", [])
        # Only the real link survives; the in-backtick example is gone.
        targets = [a.split("::", 1)[1] for a in ann]
        assert "path" not in targets
        assert "exists.md" in targets


# ── _resolve_glob_targets exclude_dirs ────────────────────────────────


class TestResolveGlobExcludeDirs:
    """Glob targets respect `.ails/config.yml: exclude_dirs`."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_excluded_dir_filtered(self, tmp_path: Path) -> None:
        # Project with a kept file and an excluded one
        (tmp_path / "CLAUDE.md").write_text("# root\n")
        excl_dir = tmp_path / "vendor"
        excl_dir.mkdir()
        (excl_dir / "stub.md").write_text("# vendor\n")
        # Write minimal .ails/config.yml excluding `vendor`
        (tmp_path / ".ails").mkdir()
        (tmp_path / ".ails" / "config.yml").write_text("exclude_dirs:\n  - vendor\n")

        # Clear caches between tmp_path runs (cache key is per-root)
        _glob_cache.clear()
        _exclude_cache.clear()

        results = _resolve_glob_targets("**/*.md", tmp_path)
        names = {p.name for p in results}
        assert "CLAUDE.md" in names
        assert "stub.md" not in names

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_config_no_exclude(self, tmp_path: Path) -> None:
        # No `.ails/config.yml` — every .md file under root surfaces.
        (tmp_path / "CLAUDE.md").write_text("# root\n")
        sub = tmp_path / "deep"
        sub.mkdir()
        (sub / "nested.md").write_text("# nested\n")

        _glob_cache.clear()
        _exclude_cache.clear()

        results = _resolve_glob_targets("**/*.md", tmp_path)
        names = {p.name for p in results}
        assert {"CLAUDE.md", "nested.md"} <= names


# ── _get_target_files intersection with classified_files ──────────────


class TestGetTargetFilesNarrowing:
    """`args.path` globs are intersected with `classified_files`.

    Regression: targeted `ails check agent:lead` ran broken-link
    extraction against every `.md` in the project because `path: "**/*.md"`
    bypassed the narrowed classified set, then attributed the cross-file
    finding to the agent's file.
    """

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_path_glob_intersects_classified_files(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# root\n")
        other = tmp_path / "other.md"
        other.write_text("# other\n")

        _glob_cache.clear()
        _exclude_cache.clear()

        # Caller narrowed classified_files to other.md only — CLAUDE.md must
        # drop out of the glob result even though the `**/*.md` pattern matches it.
        cf = ClassifiedFile(path=other, file_type="generic", properties={})
        result = _get_target_files({"path": "**/*.md"}, [cf], tmp_path)
        assert result == [other]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_narrowing_drops_cross_file_link_source(self, tmp_path: Path) -> None:
        # Regression: a broken link in `CLAUDE.md` must not surface under
        # `agent:<name>` focus. With classified narrowed to the agent file,
        # the `**/*.md` glob path resolves to a list that excludes CLAUDE.md,
        # so extract_markdown_links yields no annotations and the rule passes.
        (tmp_path / "CLAUDE.md").write_text("[broken](missing/path.md)\n")
        lead = tmp_path / "lead.md"
        lead.write_text("# clean lead\n")

        _glob_cache.clear()
        _exclude_cache.clear()

        cf = ClassifiedFile(path=lead, file_type="subagent", properties={})
        result = _get_target_files({"path": "**/*.md"}, [cf], tmp_path)
        assert result == [lead]
        assert tmp_path / "CLAUDE.md" not in result

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_path_glob_unaffected_when_classified_empty(self, tmp_path: Path) -> None:
        # Fixture harness path: no classified context → glob result returned as-is.
        (tmp_path / "CLAUDE.md").write_text("# root\n")
        (tmp_path / "other.md").write_text("# other\n")

        _glob_cache.clear()
        _exclude_cache.clear()

        result = _get_target_files({"path": "**/*.md"}, [], tmp_path)
        names = {p.name for p in result}
        assert {"CLAUDE.md", "other.md"} <= names

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_whole_project_classified_keeps_all_md_instruction_files(self, tmp_path: Path) -> None:
        # Whole-project mode: classified covers every instruction file; the
        # intersection should be a no-op for in-scope files and drop the rest.
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# root\n")
        notes = tmp_path / "docs" / "notes.md"
        notes.parent.mkdir()
        notes.write_text("# notes\n")

        _glob_cache.clear()
        _exclude_cache.clear()

        # Only CLAUDE.md is an instruction file; docs/notes.md isn't classified.
        cf = ClassifiedFile(path=claude_md, file_type="main", properties={})
        result = _get_target_files({"path": "**/*.md"}, [cf], tmp_path)
        assert result == [claude_md]


# ── _relativize ───────────────────────────────────────────────────────


class TestRelativize:
    """Pure path/root helper: under root → root-relative; else basename."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_under_root_returns_relative(self, tmp_path: Path) -> None:
        path = tmp_path / "src" / "x.py"
        assert _relativize(path, tmp_path) == "src/x.py"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_outside_root_returns_basename(self, tmp_path: Path) -> None:
        path = Path.home() / ".claude" / "CLAUDE.md"
        # No classifier context here — _relativize does not consult home.
        assert _relativize(path, tmp_path) == "CLAUDE.md"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_root_returns_basename(self) -> None:
        path = Path.home() / ".claude" / "CLAUDE.md"
        assert _relativize(path, None) == "CLAUDE.md"


# ── _classified_display ───────────────────────────────────────────────


class TestClassifiedDisplay:
    """User-scope rendering is gated on classifier `precedence`, not path-prefix."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_project_scope_under_root_relative(self, tmp_path: Path) -> None:
        path = tmp_path / "CLAUDE.md"
        cf = ClassifiedFile(
            path=path,
            file_type="main",
            properties={"precedence": "project"},
        )
        assert _classified_display(cf, tmp_path) == "CLAUDE.md"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_user_precedence_outside_root_uses_tilde(self, tmp_path: Path) -> None:
        path = Path.home() / ".claude" / "CLAUDE.md"
        cf = ClassifiedFile(
            path=path,
            file_type="main",
            properties={"precedence": "user"},
        )
        assert _classified_display(cf, tmp_path) == "~/.claude/CLAUDE.md"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unknown_precedence_outside_root_falls_back_to_basename(self, tmp_path: Path) -> None:
        # Path lives under HOME but classifier didn't mark it user-scope —
        # don't synthesize a `~/` prefix; fall back to basename.
        path = Path.home() / "some-other-file.md"
        cf = ClassifiedFile(path=path, file_type="main", properties={})
        assert _classified_display(cf, tmp_path) == "some-other-file.md"


# ── _first_classified_path ────────────────────────────────────────────


class TestFirstClassifiedPath:
    """Project-scope preference for project-wide rule attribution."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_project_scope_main_returned(self, tmp_path: Path) -> None:
        project_main = tmp_path / "CLAUDE.md"
        project_main.write_text("# project\n")
        cf = ClassifiedFile(path=project_main, file_type="main", properties={})
        result = _first_classified_path([cf], tmp_path, "main")
        assert result == "CLAUDE.md"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_user_scope_main_skipped_when_no_project_match(self, tmp_path: Path) -> None:
        # User-scope path lives under ~/.claude/ — not under tmp_path.
        user_main = Path.home() / ".claude" / "CLAUDE.md"
        cf = ClassifiedFile(path=user_main, file_type="main", properties={})
        result = _first_classified_path([cf], tmp_path, "main")
        assert result is None

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_project_preferred_over_user(self, tmp_path: Path) -> None:
        project_main = tmp_path / "CLAUDE.md"
        project_main.write_text("# project\n")
        user_main = Path.home() / ".claude" / "CLAUDE.md"
        cfs = [
            ClassifiedFile(path=user_main, file_type="main", properties={}),
            ClassifiedFile(path=project_main, file_type="main", properties={}),
        ]
        result = _first_classified_path(cfs, tmp_path, "main")
        assert result == "CLAUDE.md"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_match_returns_none(self, tmp_path: Path) -> None:
        cf = ClassifiedFile(
            path=tmp_path / "x.md",
            file_type="skill",
            properties={},
        )
        result = _first_classified_path([cf], tmp_path, "main")
        assert result is None
