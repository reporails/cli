"""Unit tests for the 0.5.10 lint-pipeline scope correctness fixes.

Covers:
- `_strip_code_spans` in `core/lint/mechanical/checks_advanced.py` and the
  mirror in `core/classify/link_walker.py` — `[text](path)` inside backticks
  must not surface as a real link.
- `_resolve_glob_targets` in `core/lint/mechanical/checks.py` — `args.path`
  globs must honor `.ails/config.yml: exclude_dirs`.
- `_relativize` in `core/lint/mechanical/runner.py` — paths outside the
  project root must serialize as `~/<rel>` when under home, not just
  `path.name`.
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
        f.write_text(
            "Describes link syntax: `[text](path)` is documentation.\n\n"
            "Real link: [target](exists.md)\n"
        )
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


# ── _relativize ───────────────────────────────────────────────────────


class TestRelativize:
    """Paths under root → root-relative; under home → ~/...; else basename."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_under_root_returns_relative(self, tmp_path: Path) -> None:
        path = tmp_path / "src" / "x.py"
        assert _relativize(path, tmp_path) == "src/x.py"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_under_home_outside_root_returns_tilde(self, tmp_path: Path) -> None:
        # Construct a path that is under HOME but not under tmp_path.
        home = Path.home()
        path = home / ".claude" / "CLAUDE.md"
        # Don't actually create the file — _relativize is path-string-only.
        result = _relativize(path, tmp_path)
        assert result == "~/.claude/CLAUDE.md"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_root_under_home_returns_tilde(self) -> None:
        path = Path.home() / ".claude" / "CLAUDE.md"
        result = _relativize(path, None)
        assert result == "~/.claude/CLAUDE.md"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_outside_root_and_home_falls_back_to_name(self, tmp_path: Path) -> None:
        # An absolute path under neither root nor home: `/etc/something.md`
        # (use a path that exists on POSIX so `is_absolute()` is unambiguous).
        path = Path("/etc/hostname")
        # Result is either project-relative (won't be) or `~/...` (won't be) or name.
        result = _relativize(path, tmp_path)
        # Either name-fallback or `~/...` depending on whether /etc is under home.
        assert result in {"hostname", "~/" + str(path).lstrip("/")}


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
