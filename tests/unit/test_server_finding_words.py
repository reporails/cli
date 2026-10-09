"""A finding the server sends without words reads as its bundled rule, in every surface."""

from __future__ import annotations

import pytest

from reporails_cli.core.lint.rule_pages import rule_title
from reporails_cli.core.platform.adapters.api_client import _deserialize_per_file
from reporails_cli.core.platform.dto.diagnostics import FileAnalysis, RulesetReport
from reporails_cli.core.platform.runtime.merger import merge_results
from reporails_cli.formatters.mcp import with_rule_labels
from reporails_cli.formatters.mcp_view import render_text_view
from reporails_cli.formatters.text import triage_view

RULE = "CORE:S:0012"
TITLE = "Agent Documents Filenames"


def _bare_reply() -> RulesetReport:
    wire = {"per_file": [{"file": "AGENTS.md", "diagnostics": [{"line": 3, "severity": "warning", "rule": RULE}]}]}
    per_file: tuple[FileAnalysis, ...] = _deserialize_per_file(wire)
    return RulesetReport(per_file=per_file)


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_rule_title_reads_the_bundled_title() -> None:
    assert rule_title(RULE) == TITLE


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_rule_title_of_an_unknown_rule_is_empty() -> None:
    assert rule_title("CORE:Z:9999") == ""


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_merged_server_finding_without_words_takes_the_rule_title_and_no_fix() -> None:
    result = merge_results([], [], _bare_reply())
    [finding] = result.findings
    assert (finding.message, finding.fix) == (TITLE, "")


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_check_text_output_shows_the_rule_title(monkeypatch: pytest.MonkeyPatch) -> None:
    [finding] = merge_results([], [], _bare_reply()).findings
    lines: list[str] = []
    monkeypatch.setattr(triage_view.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a)))
    triage_view.print_file_card("AGENTS.md", [finding], {"error": "X", "warning": "!", "info": "i"}, False, None)
    assert TITLE in "\n".join(lines)


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_mcp_text_view_shows_the_rule_title_for_a_bare_workflow_finding() -> None:
    payload = with_rule_labels(
        {
            "workflow": {
                "targets": {"tokens": ["@main"], "locations": 1, "of": 1},
                "locations": [
                    {
                        "order": 1,
                        "element": "AGENTS.md",
                        "kind": "main",
                        "loading": "always",
                        "files": ["AGENTS.md"],
                        "importance": "gate_mover",
                        "findings": [
                            {"rule": RULE, "file": "AGENTS.md", "line": 3, "op": "split", "expect": {}, "members": []}
                        ],
                        "relations": [],
                    }
                ],
            }
        }
    )
    text = render_text_view(payload)
    assert TITLE in text and "op: split" in text


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_feedback_entry_of_a_bare_workflow_finding_reads_as_title_and_op() -> None:
    from reporails_cli.interfaces.mcp.feedback import _shaped

    entry = _shaped({"rule": RULE, "line": 3, "op": "move", "impact_tier": "cosmetic"})
    assert entry["message"] == TITLE and entry["op"] == "move" and "remedy" not in entry


OVERLAP = "CORE:C:0044"
ICONS = {"error": "X", "warning": "!", "info": "i"}


def _overlap_lines(monkeypatch: pytest.MonkeyPatch, diag: dict, partners: list[str] | None = None) -> str:
    wire = {
        "per_file": [{"file": "AGENTS.md", "diagnostics": [{"line": 1, "severity": "info", "rule": OVERLAP, **diag}]}]
    }
    report = RulesetReport(per_file=_deserialize_per_file(wire))
    [finding] = merge_results([], [], report).findings
    lines: list[str] = []
    monkeypatch.setattr(triage_view.console, "print", lambda *a, **k: lines.append(" ".join(str(x) for x in a)))
    triage_view.print_file_card(
        "AGENTS.md", [finding], ICONS, False, None, partners_of=(lambda _f: partners) if partners else None
    )
    return "\n".join(lines)


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_overlap_card_names_partner_and_percent_from_the_structured_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    text = _overlap_lines(monkeypatch, {"partner_file": "docs/GUIDE.md", "overlap_pct": 40})
    assert "overlaps 40% with" in text and "GUIDE.md" in text


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_overlap_card_without_the_fields_names_partner_from_cross_file_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    text = _overlap_lines(monkeypatch, {}, partners=["docs/GUIDE.md"])
    assert "overlaps with" in text and "GUIDE.md" in text and "%" not in text


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_partner_lookup_reads_cross_file_rows(tmp_path: object) -> None:
    from pathlib import Path
    from types import SimpleNamespace

    from reporails_cli.core.platform.dto.diagnostics import CrossFileFinding
    from reporails_cli.formatters.text.display_constants import partner_lookup

    row = CrossFileFinding(file_1="AGENTS.md", file_2="docs/GUIDE.md", line_1=1, line_2=2, finding_type="overlap")
    lookup = partner_lookup(SimpleNamespace(cross_file=(row,), cross_file_coordinates=()), Path(str(tmp_path)))
    assert lookup("AGENTS.md") == ["docs/GUIDE.md"] and lookup("docs/GUIDE.md") == ["AGENTS.md"]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_no_co_load_reason_has_its_own_sentence() -> None:
    from reporails_cli.core.heal.op_guide import op_lines
    from reporails_cli.formatters.listed_reasons import listed_reason_text

    assert "never load together" in listed_reason_text("no-co-load")
    assert "Move this line" in op_lines({"hoist"})["hoist"]
