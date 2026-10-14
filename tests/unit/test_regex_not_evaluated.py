"""A check whose pattern search ran out of time is unevaluated: no finding, and it is reported."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from reporails_cli.core.lint.regex import matching, runner
from reporails_cli.core.lint.regex.not_evaluated import (
    PatternTimeoutError,
    not_evaluated_scope,
    record_not_evaluated,
)
from reporails_cli.core.platform.runtime.merger import CombinedResult, Omissions
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters.text.not_evaluated import print_not_evaluated

_CHECKS = """\
checks:
- id: CORE.X.0001.needs-heading
  expect: present
  message: needs a heading
  pattern-regex: (?m)^# \\S
  type: deterministic
  severity: low
- id: CORE.X.0002.no-secret
  expect: absent
  message: secret found
  pattern-regex: SECRET
  type: deterministic
  severity: low
"""


def _project(tmp_path: Path, text: str) -> tuple[Path, Path]:
    (tmp_path / "CLAUDE.md").write_text(text, encoding="utf-8")
    yml = tmp_path / "checks.yml"
    yml.write_text(_CHECKS, encoding="utf-8")
    return yml, tmp_path


def _run(yml: Path, root: Path) -> list[object]:
    return runner.run_checks([yml], root, instruction_files=[root / "CLAUDE.md"])


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_finished_checks_still_report(tmp_path: Path) -> None:
    """Baseline: with no timeout a missing heading is a finding and a present secret is a finding."""
    yml, root = _project(tmp_path, "no heading, SECRET here\n")
    with not_evaluated_scope() as unfinished:
        findings = _run(yml, root)
    assert {f.rule for f in findings} == {"CORE:X:0001", "CORE:X:0002"}
    assert unfinished == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_timed_out_search_gives_no_finding_for_either_expect_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yml, root = _project(tmp_path, "no heading, SECRET here\n")

    def _timeout(pat: object, content: str) -> None:
        raise PatternTimeoutError("forced")

    monkeypatch.setattr(matching, "safe_search", _timeout)
    with not_evaluated_scope() as unfinished:
        findings = _run(yml, root)
    assert findings == []
    assert sorted(set(unfinished)) == [("CORE:X:0001", "CLAUDE.md"), ("CORE:X:0002", "CLAUDE.md")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_real_catastrophic_pattern_runs_out_of_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    yml, root = _project(tmp_path, "# title\n" + "a" * 60 + "b\n")
    yml.write_text(
        _CHECKS.replace("(?m)^# \\S", "(a|aa)+$"),
        encoding="utf-8",
    )
    monkeypatch.setattr(matching, "REGEX_TIMEOUT_S", 0.05)
    with not_evaluated_scope() as unfinished:
        findings = _run(yml, root)
    assert ("CORE:X:0001", "CLAUDE.md") in unfinished
    assert all(f.rule != "CORE:X:0001" for f in findings)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_nothing_recorded_outside_a_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    record_not_evaluated("CORE:X:0001", "a.md")
    with not_evaluated_scope() as unfinished:
        pass
    assert unfinished == []

    yml, root = _project(tmp_path, "x\n")
    monkeypatch.setattr(matching, "safe_search", lambda *_a: (_ for _ in ()).throw(PatternTimeoutError("forced")))
    assert _run(yml, root) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_scopes_nest_without_leaking() -> None:
    with not_evaluated_scope() as outer:
        record_not_evaluated("CORE:X:0001", "a.md")
        with not_evaluated_scope() as inner:
            record_not_evaluated("CORE:X:0002", "b.md")
        record_not_evaluated("CORE:X:0003", "c.md")
    assert inner == [("CORE:X:0002", "b.md")]
    assert outer == [("CORE:X:0001", "a.md"), ("CORE:X:0003", "c.md")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_json_envelope_lists_not_evaluated(tmp_path: Path) -> None:
    empty = json_formatter.format_combined_result(CombinedResult(), project_root=tmp_path)
    assert empty["not_evaluated"] == []
    result = CombinedResult(omissions=Omissions(not_evaluated=(("CORE:C:0037", "docs/big.md"),)))
    data = json_formatter.format_combined_result(result, project_root=tmp_path)
    assert data["not_evaluated"] == [{"rule": "CORE:C:0037", "file": "docs/big.md"}]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_text_line_is_dim_and_only_when_present() -> None:
    quiet = Console(file=StringIO(), width=200, force_terminal=False)
    print_not_evaluated(quiet, ())
    assert quiet.file.getvalue() == ""  # type: ignore[attr-defined]

    buf = StringIO()
    print_not_evaluated(Console(file=buf, width=200, force_terminal=False), (("CORE:C:0037", "docs/big.md"),))
    assert "Not evaluated in docs/big.md: CORE:C:0037 — the check did not finish in time" in buf.getvalue()


def _timeout_on(*needles: str, fn: str) -> object:
    real = getattr(matching, fn)

    def _wrapped(pat: object, content: str) -> object:
        if any(n in getattr(pat, "pattern", "") for n in needles):
            raise PatternTimeoutError("forced")
        return real(pat, content)

    return _wrapped


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_confirmed_absent_match_survives_a_timed_out_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    yml, root = _project(tmp_path, "# title\nSECRET here\n")
    monkeypatch.setattr(matching, "safe_finditer", _timeout_on("SECRET", fn="safe_finditer"))
    with not_evaluated_scope() as unfinished:
        findings = _run(yml, root)
    assert [f.rule for f in findings] == ["CORE:X:0002"]
    assert unfinished == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_either_pattern_check_reports_when_one_pattern_times_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "CLAUDE.md").write_text("# title\nTOKEN here\n", encoding="utf-8")
    yml = tmp_path / "checks.yml"
    yml.write_text(
        "checks:\n- id: CORE.X.0003.either\n  expect: absent\n  message: found\n  type: deterministic\n"
        "  severity: low\n  pattern-either:\n  - pattern-regex: SLOWONE\n  - pattern-regex: TOKEN\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(matching, "safe_search", _timeout_on("SLOWONE", fn="safe_search"))
    monkeypatch.setattr(matching, "safe_finditer", _timeout_on("SLOWONE", fn="safe_finditer"))
    with not_evaluated_scope() as unfinished:
        findings = _run(yml, tmp_path)
    assert [f.rule for f in findings] == ["CORE:X:0003"]
    assert unfinished == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_timeout_is_recorded_only_for_a_file_the_check_applies_to(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "small.md").write_text("one\n", encoding="utf-8")
    (tmp_path / "big.md").write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")
    yml = tmp_path / "checks.yml"
    yml.write_text(
        "checks:\n- id: CORE.X.0004.long\n  expect: present\n  message: m\n  type: deterministic\n"
        "  severity: low\n  min_lines: 3\n  pattern-regex: NEVER\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(matching, "safe_search", lambda *_a: (_ for _ in ()).throw(PatternTimeoutError("forced")))
    with not_evaluated_scope() as unfinished:
        runner.run_checks([yml], tmp_path, instruction_files=[tmp_path / "small.md", tmp_path / "big.md"])
    assert unfinished == [("CORE:X:0004", "big.md")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_timeout_on_a_non_entry_file_is_not_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "SKILL.md").write_text("x\n", encoding="utf-8")
    (tmp_path / "other.md").write_text("x\n", encoding="utf-8")
    yml = tmp_path / "checks.yml"
    yml.write_text(
        "checks:\n- id: CORE.X.0005.entry\n  expect: present\n  message: m\n  type: deterministic\n"
        "  severity: low\n  entry_only: true\n  pattern-regex: NEVER\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(matching, "safe_search", lambda *_a: (_ for _ in ()).throw(PatternTimeoutError("forced")))
    with not_evaluated_scope() as unfinished:
        runner.run_checks(
            [yml],
            tmp_path,
            instruction_files=[tmp_path / "SKILL.md", tmp_path / "other.md"],
            skill_entries={(tmp_path / "SKILL.md").resolve()},
        )
    assert unfinished == [("CORE:X:0005", "SKILL.md")]
