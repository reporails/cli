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
        from reporails_cli.interfaces.cli.check_orchestration import _should_exit_strict

        # A finding on a user-scope file, carrying the normalized `~/...` form.
        user_file = Path.home() / ".claude" / "subagent_memory.md"
        finding = _Finding(file="~/.claude/subagent_memory.md")
        result = _Result(findings=(finding,))

        assert _should_exit_strict(True, {user_file}, tmp_path, result) is True

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_strict_no_exit_when_finding_outside_scope(self, tmp_path: Path) -> None:
        from reporails_cli.interfaces.cli.check_orchestration import _should_exit_strict

        user_file = Path.home() / ".claude" / "subagent_memory.md"
        result = _Result(findings=(_Finding(file="other.md"),))
        assert _should_exit_strict(True, {user_file}, tmp_path, result) is False


class TestStrictExitOnRejectedKey:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_strict_exits_on_rejected_key_with_no_local_findings(self, tmp_path: Path) -> None:
        """Regression: a revoked or unknown `AILS_API_KEY` returned exit 0 under `--strict`
        whenever the tree itself carried no local findings, because `_should_exit_strict`
        only ever looked at `result.findings`. An auth rejection must fail `--strict` on
        its own, independent of whether the target has anything else wrong with it."""
        from reporails_cli.core.platform.dto.diagnostics import FunnelError
        from reporails_cli.interfaces.cli.check_orchestration import _should_exit_strict

        result = _Result(findings=())
        rejected = FunnelError(error="invalid_api_key", status=401)

        assert _should_exit_strict(True, set(), tmp_path, result, rejected) is True

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_plain_run_stays_zero_on_rejected_key(self, tmp_path: Path) -> None:
        """A plain (non-strict) run never turns the auth rejection into a new exit
        code — it stays 0 and the message alone carries the news."""
        from reporails_cli.core.platform.dto.diagnostics import FunnelError
        from reporails_cli.interfaces.cli.check_orchestration import _should_exit_strict

        result = _Result(findings=())
        rejected = FunnelError(error="invalid_api_key", status=401)

        assert _should_exit_strict(False, set(), tmp_path, result, rejected) is False

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_strict_unaffected_by_an_unrelated_funnel_error(self, tmp_path: Path) -> None:
        """A non-auth funnel error (e.g. a rate limit) must not itself trip `--strict` —
        only the two auth-rejection tokens do."""
        from reporails_cli.core.platform.dto.diagnostics import FunnelError
        from reporails_cli.interfaces.cli.check_orchestration import _should_exit_strict

        result = _Result(findings=())
        rate_limited = FunnelError(error="rate_limit_exceeded", status=429)

        assert _should_exit_strict(True, set(), tmp_path, result, rate_limited) is False


class TestExcludeFilesDropsLinkWalked:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_link_walked_left_out_file_is_not_classified(self, tmp_path: Path) -> None:
        """The @import link walk does not reach a file the run left out."""
        from reporails_cli.core.discovery.exclusions import parse_run_exclusions
        from reporails_cli.core.lint.rule_runner import _classify_agent_files

        (tmp_path / "CLAUDE.md").write_text("# P\n\n@VENDORED.md\n\n@other.md\n", encoding="utf-8")
        (tmp_path / "VENDORED.md").write_text("Always lint.\n", encoding="utf-8")
        (tmp_path / "other.md").write_text("Always test.\n", encoding="utf-8")
        (tmp_path / ".ails").mkdir()
        (tmp_path / ".ails" / "config.yml").write_text("generic_scanning: true\n", encoding="utf-8")
        exclusions = parse_run_exclusions(tmp_path, (), ("VENDORED.md",))

        classified, _ = _classify_agent_files(tmp_path, [tmp_path / "CLAUDE.md"], "claude", exclusions=exclusions)
        names = {cf.path.name for cf in classified}
        assert names == {"CLAUDE.md", "other.md"}
