"""Tests for interfaces/cli/heal.py — section suggestions are collected, never written,
and rendered under their own heading/key, separate from applied (mechanical) fixes.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.interfaces.cli.heal import _collect_section_suggestions, _output_heal_results


class _Console:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, msg: str = "") -> None:
        self.lines.append(msg)


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_collect_section_suggestions_does_not_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A sparse CLAUDE.md missing sections is left byte-identical; findings surface as suggestions."""
    fpath = tmp_path / "CLAUDE.md"
    original = "# Demo\n\nThis project is a small Python tool.\n\nWrite clear code.\n"
    fpath.write_text(original, encoding="utf-8")

    def _fake_probes(*_a: Any, **_k: Any) -> list[LocalFinding]:
        return [LocalFinding(file="CLAUDE.md", line=0, severity="warning", rule="CORE:C:0035", message="missing")]

    def _fake_content(*_a: Any, **_k: Any) -> list[LocalFinding]:
        # CORE:C:0019/C:0010/C:0005/S:0016 are content_query checks — they need the
        # mapped ruleset_map, not the M-probe pass, so they arrive through this call.
        return [
            LocalFinding(file="CLAUDE.md", line=0, severity="warning", rule="CORE:C:0019", message="missing"),
            LocalFinding(file="CLAUDE.md", line=0, severity="warning", rule="CORE:C:0010", message="missing"),
        ]

    monkeypatch.setattr("reporails_cli.core.lint.rule_runner.run_m_probes", _fake_probes)
    monkeypatch.setattr("reporails_cli.core.lint.rule_runner.run_content_quality_checks", _fake_content)

    suggestions = _collect_section_suggestions(tmp_path, [fpath], object(), "claude", False, _Console())

    assert fpath.read_text(encoding="utf-8") == original
    assert {s["rule_id"] for s in suggestions} == {"CORE:C:0019", "CORE:C:0010", "CORE:C:0035"}
    sections = {s["section"] for s in suggestions}
    assert "## Constraints" in sections
    assert "## Commands" in sections
    assert "## Project Structure" in sections
    for s in suggestions:
        assert s["file_path"] == "CLAUDE.md"
        assert "TODO" not in s["description"]


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_collect_section_suggestions_honors_inline_suppression(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A finding suppressed on its line with `<!-- ails-disable-line <rule> -->` — the
    same directive the main report honors — must not turn into a heal suggestion."""
    fpath = tmp_path / "CLAUDE.md"
    original = "# Demo\n\nThis project is a small Python tool. <!-- ails-disable-line CORE:C:0019 -->\n"
    fpath.write_text(original, encoding="utf-8")

    def _fake_probes(*_a: Any, **_k: Any) -> list[LocalFinding]:
        return []

    def _fake_content(*_a: Any, **_k: Any) -> list[LocalFinding]:
        return [LocalFinding(file="CLAUDE.md", line=3, severity="warning", rule="CORE:C:0019", message="missing")]

    monkeypatch.setattr("reporails_cli.core.lint.rule_runner.run_m_probes", _fake_probes)
    monkeypatch.setattr("reporails_cli.core.lint.rule_runner.run_content_quality_checks", _fake_content)

    suggestions = _collect_section_suggestions(tmp_path, [fpath], object(), "claude", False, _Console())

    assert suggestions == []
    assert fpath.read_text(encoding="utf-8") == original


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_collect_section_suggestions_still_fires_on_an_unsuppressed_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The suppression directive only silences the finding on ITS OWN line — a finding
    on any other line still turns into a suggestion."""
    fpath = tmp_path / "CLAUDE.md"
    original = "# Demo\n\nThis project is a small Python tool.\n"
    fpath.write_text(original, encoding="utf-8")

    def _fake_probes(*_a: Any, **_k: Any) -> list[LocalFinding]:
        return []

    def _fake_content(*_a: Any, **_k: Any) -> list[LocalFinding]:
        return [LocalFinding(file="CLAUDE.md", line=3, severity="warning", rule="CORE:C:0019", message="missing")]

    monkeypatch.setattr("reporails_cli.core.lint.rule_runner.run_m_probes", _fake_probes)
    monkeypatch.setattr("reporails_cli.core.lint.rule_runner.run_content_quality_checks", _fake_content)

    suggestions = _collect_section_suggestions(tmp_path, [fpath], object(), "claude", False, _Console())

    assert {s["rule_id"] for s in suggestions} == {"CORE:C:0019"}


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_output_heal_results_json_carries_suggested_list_and_count() -> None:
    mech = [{"rule_id": "M1", "file_path": "CLAUDE.md", "line": 3, "description": "fixed bold"}]
    suggested = [
        {"rule_id": "CORE:C:0019", "file_path": "CLAUDE.md", "section": "## Constraints", "description": "..."}
    ]

    buf = io.StringIO()
    with redirect_stdout(buf):
        _output_heal_results(mech, suggested, False, 12.3, "json", _Console())

    data = json.loads(buf.getvalue())
    assert data["auto_fixed"] == mech
    assert data["suggested"] == suggested
    assert data["summary"]["auto_fixed_count"] == 1
    assert data["summary"]["suggested_count"] == 1


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_output_heal_results_text_lists_suggestions_under_their_own_heading() -> None:
    suggested = [
        {"rule_id": "CORE:C:0019", "file_path": "CLAUDE.md", "section": "## Constraints", "description": "..."}
    ]
    console = _Console()

    _output_heal_results([], suggested, False, 5.0, "text", console)

    joined = "\n".join(console.lines)
    assert "Sections to add (not written):" in joined
    assert "CLAUDE.md" in joined
    assert "## Constraints" in joined
    # No applied fixes: the applied-count line does not claim any were made.
    assert "No fixes applied." in joined
    assert "fixes applied" not in joined.replace("No fixes applied.", "")


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_output_heal_results_text_reports_no_fixable_issues_when_nothing_found() -> None:
    console = _Console()

    _output_heal_results([], [], False, 5.0, "text", console)

    joined = "\n".join(console.lines)
    assert "No fixable issues found." in joined
    assert "Sections to add" not in joined
