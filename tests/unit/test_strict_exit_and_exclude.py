"""Regression tests for two 0.5.12 fixes lacking a natural home: strict-exit
path-form alignment and the `exclude_files` re-filter on the `@import` link-walk.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass
class _Finding:
    file: str


@dataclass
class _Result:
    findings: tuple[_Finding, ...]


class TestStrictExitPathNormalization:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_strict_exits_on_user_scope_target_with_displayed_error(self, tmp_path: Path) -> None:
        """Regression: `_should_exit_strict` keyed `capability_paths` with `_relativize_paths`
        while the display filter used `normalize_finding_path`. For a user-scope (`~/...`)
        target the two diverged, so a strict run could exit 0 despite a displayed error.
        The membership must use the same normalization the finding path carries."""
        from reporails_cli.interfaces.cli.main import _should_exit_strict

        # A finding on a user-scope file, carrying the normalized `~/...` form.
        user_file = Path.home() / ".claude" / "subagent_memory.md"
        finding = _Finding(file="~/.claude/subagent_memory.md")
        result = _Result(findings=(finding,))

        assert _should_exit_strict(True, {user_file}, tmp_path, result) is True

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_strict_no_exit_when_finding_outside_scope(self, tmp_path: Path) -> None:
        from reporails_cli.interfaces.cli.main import _should_exit_strict

        user_file = Path.home() / ".claude" / "subagent_memory.md"
        result = _Result(findings=(_Finding(file="other.md"),))
        assert _should_exit_strict(True, {user_file}, tmp_path, result) is False


class TestExcludeFilesDropsLinkWalked:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_drop_excluded_filters_classified(self, tmp_path: Path) -> None:
        """Regression: the @import link-walk re-discovered files agent discovery already
        excluded. `_drop_excluded` re-applies exclude_files to the classified set."""
        from reporails_cli.core.lint.rule_runner import _drop_excluded

        @dataclass
        class _CF:
            path: Path

        keep = _CF(path=tmp_path / "CLAUDE.md")
        drop = _CF(path=tmp_path / "VENDORED.md")

        out = _drop_excluded([keep, drop], ["VENDORED.md"], tmp_path)

        assert keep in out
        assert drop not in out

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_drop_excluded_noop_without_patterns(self, tmp_path: Path) -> None:
        from reporails_cli.core.lint.rule_runner import _drop_excluded

        @dataclass
        class _CF:
            path: Path

        items = [_CF(path=tmp_path / "a.md")]
        assert _drop_excluded(items, None, tmp_path) == items

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_drop_excluded_keeps_explicitly_targeted_file(self, tmp_path: Path) -> None:
        """An explicitly-targeted file matching an exclude glob is NOT dropped — naming a
        file overrides the project exclusion. Regression: filtering the full classified
        set returned a falsely-clean empty result for a file the user asked to validate."""
        from reporails_cli.core.lint.rule_runner import _drop_excluded

        @dataclass
        class _CF:
            path: Path

        explicit = _CF(path=tmp_path / "VENDORED.md")
        walked = _CF(path=tmp_path / "other_VENDORED.md")

        out = _drop_excluded([explicit, walked], ["*VENDORED.md"], tmp_path, keep=[explicit.path])

        assert explicit in out, "explicitly-targeted file was wrongly excluded"
        assert walked not in out, "link-walked excluded file should still be dropped"
