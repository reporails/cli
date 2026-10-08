"""A settings, hook or MCP config file takes no rewrite location; its findings are listed."""

from __future__ import annotations

from typing import Any

import pytest

from reporails_cli.core.lint.suppression import (
    CONFIG_LISTED_REASON,
    apply_config_listing,
    list_config_locations,
)
from reporails_cli.core.platform.adapters.workflow_wire import deserialize_workflow
from reporails_cli.core.platform.runtime.merger import CombinedResult, CombinedStats, FindingItem

CFG = ".claude/settings.local.json"
RULE_A = "CORE:E:0004"
RULE_B = "CORE:D:0003"


def _row(rule: str, file: str, line: int = 2) -> dict[str, Any]:
    return {
        "rule": rule, "file": file, "line": line, "pi": 0, "message": "m", "remedy": "r",
        "impact_tier": "gate_mover", "members": [],
    }  # fmt: skip


def _loc(order: int, kind: str, files: list[str], rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"order": order, "element": files[0], "kind": kind, "loading": "always", "files": files, "findings": rows}


def _wf(locations: list[dict[str, Any]], listed: list[dict[str, Any]] | None = None) -> Any:
    wf = deserialize_workflow({"workflow": {"summary": "stale", "locations": locations, "listed": listed or []}})
    assert wf is not None
    return wf


def _norm(f: str) -> str:
    return f


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_config_location_is_listed_and_the_rest_renumbered() -> None:
    wf = _wf(
        [
            _loc(1, "config", [CFG], [_row(RULE_A, CFG), _row(RULE_A, CFG, 5), _row(RULE_B, CFG, 7)]),
            _loc(2, "skills", [".claude/skills/a/SKILL.md"], [_row(RULE_B, ".claude/skills/a/SKILL.md")]),
        ]
    )
    out = list_config_locations(wf, _norm)
    assert [(loc.order, loc.kind) for loc in out.locations] == [(1, "skills")]
    assert {(e.rule, e.count) for e in out.listed} == {(RULE_A, 2), (RULE_B, 1)}
    assert all(e.reason == CONFIG_LISTED_REASON for e in out.listed)
    assert out.summary == "1 location to rewrite, by kind: 1 skills."


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_only_config_locations_leaves_nothing_to_rewrite_and_findings_untouched() -> None:
    wf = _wf([_loc(1, "config", [CFG], [_row(RULE_A, CFG)])])
    items = (FindingItem(file=CFG, line=2, severity="warning", rule=RULE_A, message="m", source="server", pi=0),)
    result = CombinedResult(findings=items, stats=CombinedStats(total_findings=1), workflow=wf)
    out = apply_config_listing(result)
    assert out.workflow.locations == ()
    assert out.workflow.summary == "Nothing to rewrite — every finding is listed with the reason it takes none."
    assert out.findings == items


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_mixed_file_location_is_kept() -> None:
    wf = _wf([_loc(1, "main", [CFG, "CLAUDE.md"], [_row(RULE_A, CFG), _row(RULE_A, "CLAUDE.md")])])
    assert list_config_locations(wf, _norm) is wf


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_rule_already_listed_gets_its_count_added() -> None:
    wf = _wf(
        [_loc(1, "config", [CFG], [_row(RULE_A, CFG)])],
        [{"rule": RULE_A, "reason": "no_remedy", "count": 3}],
    )
    out = list_config_locations(wf, _norm)
    assert [(e.rule, e.reason, e.count) for e in out.listed] == [(RULE_A, "no_remedy", 4)]
