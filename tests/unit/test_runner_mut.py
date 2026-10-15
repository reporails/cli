"""Mutation-killing behavioral tests for the regex runner (lint/regex/runner.py).

Targets the operators that survived the mutation probe: frontmatter stripping,
path-filter globstar handling, dedup/existence guards, the OSError/ValueError
fallbacks, the None-path guards,
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

from reporails_cli.core.lint.regex.compiler import CompiledCheck, compile_rules
from reporails_cli.core.lint.regex.expect import emit_expect_findings, file_below_min_lines, file_matches_path_filter
from reporails_cli.core.lint.regex.runner import (
    _compile_ruleset,
    _is_text_file,
    _resolve_scan_targets,
    _scan_all_targets,
)
from reporails_cli.core.platform.utils.utils import strip_frontmatter


def _make_check(
    check_id: str = "C1",
    *,
    patterns: tuple[regex.Pattern[str], ...] = (),
    negative_patterns: tuple[regex.Pattern[str], ...] = (),
    either_patterns: tuple[regex.Pattern[str], ...] = (),
    path_includes: tuple[str, ...] = (),
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
    """Frontmatter whose closing '---' is the last line strips to nothing."""
    assert strip_frontmatter("---\nkey: val\n---") == ""


# ---------------------------------------------------------------------------
# file_matches_path_filter (L62)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_path_filter_globstar_matches_rel_not_filename() -> None:
    """A '**/sub/file.md' pattern matches the relative path via the collapsed form.

    Kills L62 `or->and`: the rel-path branch matches while the bare-filename
    branch does not; `and` would drop the match.
    """
    assert file_matches_path_filter("sub/file.md", ("**/sub/file.md",)) is True


# ---------------------------------------------------------------------------
# _resolve_scan_targets (L92) — existence guards
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_resolve_scan_targets_skips_nonexistent_instruction(tmp_path: Path) -> None:
    """A non-existent instruction file is not a scan target (L92 `and->or`)."""
    result = _resolve_scan_targets(tmp_path, [tmp_path / "missing.md"])
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
# _scan_file emits every match
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_scan_emits_every_match(tmp_path: Path) -> None:
    """Every match of a check is emitted, not just the first."""
    check = _make_check("M1", either_patterns=(regex.compile("alpha"), regex.compile("beta")))
    f = tmp_path / "CLAUDE.md"
    f.write_text("alpha beta", encoding="utf-8")

    sarif = _scan_all_targets([f], tmp_path, [check], {})
    results = sarif["runs"][0]["results"]
    assert sum(1 for r in results if r["ruleId"] == "M1") == 2


# ---------------------------------------------------------------------------
# _compile_ruleset None-path guard (L391)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_compile_ruleset_filters_none_path() -> None:
    """A falsy yml path is filtered out, not dereferenced (L391 `and->or`)."""
    assert _compile_ruleset([None]).checks == []  # type: ignore[list-item]


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


# ---------------------------------------------------------------------------
# emit_expect_findings (L518 rule_id, L538 message fallback)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_emit_findings_rule_id_from_three_part_check_id() -> None:
    """A 3-part check id maps to a colon-joined rule id (L518 `>=->>`)."""
    findings = emit_expect_findings(
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
    findings = emit_expect_findings(
        [replace(_make_check("C1", every_match=True), message="fallback message")],
        matched_pairs={("C1", "f.md")},
        match_details={("C1", "f.md"): [(5, "", "")]},
        scanned_files=["f.md"],
    )
    assert len(findings) == 1
    assert findings[0].message == "fallback message"


# ---------------------------------------------------------------------------
# file_below_min_lines guards (L569 or->and, L575)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_file_below_min_lines_none_scan_root() -> None:
    """A None scan_root short-circuits to False, not a None-division (L569 `or->and`)."""
    assert file_below_min_lines("f.md", 5, None) is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_file_below_min_lines_missing_file(tmp_path: Path) -> None:
    """An unreadable file is treated as not-below (L575 `False->True`)."""
    assert file_below_min_lines("missing.md", 5, tmp_path) is False
