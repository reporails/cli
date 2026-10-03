"""Mutation-killing behavioral tests for the regex runner (lint/regex/runner.py).

Targets the operators that survived the mutation probe: frontmatter stripping,
path-filter globstar handling, dedup/existence guards, the OSError/ValueError
fallbacks, combined-scan group handling, default kwargs, the None-path guards,
min_lines gating, and the finding-emission paths. Each test asserts an OUTPUT
that flips when the operator under it is mutated (verified against the probe).
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import regex
import yaml

from reporails_cli.core.lint.regex.compiler import CombinedPattern, CompiledCheck, compile_rules
from reporails_cli.core.lint.regex.runner import (
    _append_extra,
    _emit_expect_findings,
    _file_below_min_lines,
    _file_matches_path_filter,
    _is_text_file,
    _resolve_scan_targets,
    _resolve_scanned_files,
    _scan_all_targets,
    _scan_combined,
    checks_per_file,
    run_validation,
)
from reporails_cli.core.platform.utils.utils import strip_frontmatter


def _make_check(
    check_id: str = "C1",
    *,
    patterns: tuple[regex.Pattern[str], ...] = (),
    negative_patterns: tuple[regex.Pattern[str], ...] = (),
    either_patterns: tuple[regex.Pattern[str], ...] = (),
    path_includes: tuple[str, ...] = (),
    body_only: bool = False,
    every_match: bool = False,
) -> CompiledCheck:
    return CompiledCheck(
        id=check_id,
        message="m",
        severity="warning",
        patterns=patterns,
        negative_patterns=negative_patterns,
        either_patterns=either_patterns,
        path_includes=path_includes,
        body_only=body_only,
        every_match=every_match,
    )


def _write_yml(tmp_path: Path, data: dict[str, Any], name: str = "rule.yml") -> Path:
    p = tmp_path / name
    p.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _strip_frontmatter (L32)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_strip_frontmatter_closing_at_eof() -> None:
    """Frontmatter whose closing '---' is the last line strips to blank lines.

    Kills L32 `==->!=`: without the -1 -> len(content) fixup a trailing char
    leaks through.
    """
    assert strip_frontmatter("---\nkey: val\n---", keep_lines=True) == "\n\n"


# ---------------------------------------------------------------------------
# _file_matches_path_filter (L62)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_path_filter_globstar_matches_rel_not_filename() -> None:
    """A '**/sub/file.md' pattern matches the relative path via the collapsed form.

    Kills L62 `or->and`: the rel-path branch matches while the bare-filename
    branch does not; `and` would drop the match.
    """
    assert _file_matches_path_filter("sub/file.md", ("**/sub/file.md",)) is True


# ---------------------------------------------------------------------------
# _append_extra (L76) / _resolve_scan_targets (L92) — existence guards
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_append_extra_skips_nonexistent(tmp_path: Path) -> None:
    """A non-existent extra target is not appended (L76 `and->or`)."""
    seen: set[Path] = set()
    targets: list[Path] = []
    _append_extra(seen, targets, [tmp_path / "missing.md"])
    assert targets == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_resolve_scan_targets_skips_nonexistent_instruction(tmp_path: Path) -> None:
    """A non-existent instruction file is not a scan target (L92 `and->or`)."""
    result = _resolve_scan_targets(tmp_path, [tmp_path / "missing.md"], None)
    assert result == []


# ---------------------------------------------------------------------------
# _is_text_file (L113) — fallback
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_is_text_file_oserror_returns_false(tmp_path: Path) -> None:
    """An unreadable path returns False (L113 `False->True`)."""
    assert _is_text_file(tmp_path / "does-not-exist") is False


# ---------------------------------------------------------------------------
# _scan_combined — None-group guard (L303)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_scan_combined_skips_unnamed_group_match() -> None:
    """A match whose lastgroup is None is skipped, not dereferenced (L303 `and->or`)."""
    check = _make_check("G0")
    combined = CombinedPattern(
        regex=regex.compile(r"(?P<g0>foo)|(bar)"),
        group_to_check={"g0": check},
    )
    results: list[dict[str, Any]] = []
    rule_defs: dict[str, dict[str, Any]] = {}
    _scan_combined("bar", "f.md", [combined], results, rule_defs)
    assert results == []


# ---------------------------------------------------------------------------
# _scan_file default first_match_only (L324)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_scan_emits_all_matches_by_default(tmp_path: Path) -> None:
    """By default every match is emitted, not just the first (L324 `False->True`)."""
    check = _make_check("M1", either_patterns=(regex.compile("alpha"), regex.compile("beta")))
    f = tmp_path / "CLAUDE.md"
    f.write_text("alpha beta", encoding="utf-8")

    sarif = _scan_all_targets([f], tmp_path, [check], {}, frozenset())
    results = sarif["runs"][0]["results"]
    assert sum(1 for r in results if r["ruleId"] == "M1") == 2


# ---------------------------------------------------------------------------
# run_validation / checks_per_file None-path guards (L391, L656, L664)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_run_validation_filters_none_path(tmp_path: Path) -> None:
    """A falsy yml path is filtered out, not dereferenced (L391 `and->or`)."""
    assert run_validation([None], tmp_path) == {"runs": []}  # type: ignore[list-item]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_checks_per_file_filters_none_path(tmp_path: Path) -> None:
    """A falsy yml path is filtered out in checks_per_file (L656 `and->or`)."""
    assert checks_per_file([None], tmp_path, []) == {}  # type: ignore[list-item]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_checks_per_file_none_instruction_files(tmp_path: Path) -> None:
    """instruction_files=None iterates an empty list, not None (L664 `or->and`)."""
    yml = _write_yml(tmp_path, {"checks": [{"id": "R1", "pattern-regex": "a", "message": "x"}]})
    assert checks_per_file([yml], tmp_path, None) == {}


# ---------------------------------------------------------------------------
# compiled min_lines guard
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_compiled_check_ignores_nonpositive_min_lines(tmp_path: Path) -> None:
    """A min_lines of 0 or below is not recorded."""
    entries = [
        {"id": f"CORE.S.0013.c{i}", "type": "deterministic", "pattern-regex": "x", "min_lines": n, "message": "m"}
        for i, n in enumerate((0, -3, 7))
    ]
    yml = _write_yml(tmp_path, {"checks": entries})
    assert [c.min_lines for c in compile_rules([yml]).checks] == [0, 0, 7]


# ---------------------------------------------------------------------------
# _resolve_scanned_files exclusion combination (L480)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_resolve_scanned_files_excludes_by_dir_alone(tmp_path: Path) -> None:
    """A file excluded by dir alone is dropped even when file-globs don't match.

    Kills L480 `or->and`: with `and` the dir-exclusion no longer suffices.
    """
    nm = tmp_path / "node_modules"
    nm.mkdir()
    f = nm / "CLAUDE.md"
    f.write_text("x", encoding="utf-8")

    scanned = _resolve_scanned_files(
        tmp_path, instruction_files=[f], exclude_dirs=frozenset({"node_modules"}), exclude_files=None
    )
    assert scanned == []


# ---------------------------------------------------------------------------
# _emit_expect_findings (L518 rule_id, L538 message fallback)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_emit_findings_rule_id_from_three_part_check_id() -> None:
    """A 3-part check id maps to a colon-joined rule id (L518 `>=->>`)."""
    findings = _emit_expect_findings(
        [_make_check("CORE.S.0013")],
        matched_pairs=set(),
        match_details={},
        scanned_files=["f.md"],
    )
    assert len(findings) == 1
    assert findings[0].rule == "CORE:S:0013"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_emit_findings_absent_message_falls_back_to_check_message() -> None:
    """An empty match message falls back to the check message (L538 `or->and`)."""
    findings = _emit_expect_findings(
        [replace(_make_check("C1", every_match=True), message="fallback message")],
        matched_pairs={("C1", "f.md")},
        match_details={("C1", "f.md"): [(5, "", "")]},
        scanned_files=["f.md"],
    )
    assert len(findings) == 1
    assert findings[0].message == "fallback message"


# ---------------------------------------------------------------------------
# _file_below_min_lines guards (L569 or->and, L575)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_file_below_min_lines_none_scan_root() -> None:
    """A None scan_root short-circuits to False, not a None-division (L569 `or->and`)."""
    assert _file_below_min_lines("f.md", 5, None) is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_file_below_min_lines_missing_file(tmp_path: Path) -> None:
    """An unreadable file is treated as not-below (L575 `False->True`)."""
    assert _file_below_min_lines("missing.md", 5, tmp_path) is False
