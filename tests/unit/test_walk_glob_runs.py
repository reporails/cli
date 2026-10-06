"""Glob matching sees the filesystem fresh on every run, works from a relative root, and
reports a looping symlink only from the walkers that own that report."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from reporails_cli.core.discovery.agent_discovery import ci_glob
from reporails_cli.core.discovery.walk import walk_glob_matches, walk_markdown
from reporails_cli.core.lint.mechanical import runner
from reporails_cli.core.lint.mechanical.checks import _resolve_glob_targets
from reporails_cli.core.lint.mechanical.runner import run_mechanical_checks
from reporails_cli.core.platform.dto.models import Check, Rule


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_guard_mechanical_run_sees_files_created_between_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A second mechanical run in the same process finds a file created after the first."""
    skills = tmp_path / ".claude" / "skills"
    (skills / "alpha").mkdir(parents=True)
    (skills / "alpha" / "SKILL.md").write_text("x\n", encoding="utf-8")
    seen: list[list[str]] = []

    def spy(*_args: object, **_kwargs: object) -> tuple[None, None]:
        found = _resolve_glob_targets(".claude/skills/*/SKILL.md", tmp_path)
        seen.append(sorted(p.parent.name for p in found))
        return None, None

    monkeypatch.setattr(runner, "dispatch_single_check", spy)
    check = Check(id="c", type="mechanical", check="file_exists")
    rule = Rule(id="CORE:S:9999", title="t", category="structure", type="mechanical", checks=[check])

    run_mechanical_checks({rule.id: rule}, tmp_path, [])
    (skills / "beta").mkdir()
    (skills / "beta" / "SKILL.md").write_text("x\n", encoding="utf-8")
    run_mechanical_checks({rule.id: rule}, tmp_path, [])

    assert seen == [["alpha"], ["alpha", "beta"]]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_guard_relative_root_matches_glob(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".claude" / "rules").mkdir(parents=True)
    (tmp_path / ".claude" / "rules" / "x.md").write_text("x\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    expected = Path(".claude/rules/x.md")
    assert ci_glob(Path("."), ".claude/rules/*.md") == [expected]
    assert _resolve_glob_targets(".claude/rules/*.md", Path(".")) == [expected]
    assert list(walk_glob_matches(Path("."), "**/*.md", frozenset())) == [expected]


def _looping_symlink(root: Path) -> None:
    (root / "a.md").symlink_to("a.md")


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.skipif(os.name == "nt", reason="symlinks")
def test_guard_glob_walk_does_not_report_loops_but_markdown_walk_does(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _looping_symlink(tmp_path)
    caplog.set_level(logging.WARNING)
    list(walk_glob_matches(tmp_path, "*.md", frozenset()))
    glob_records = [r for r in caplog.records if "Circular symlink" in r.getMessage()]
    caplog.clear()
    list(walk_markdown(tmp_path, frozenset()))
    md_records = [r for r in caplog.records if "Circular symlink" in r.getMessage()]
    assert len(glob_records) == 0
    assert len(md_records) == 1
