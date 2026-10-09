"""The `validate` text view: its sections, the locations budget, determinism, and notices once."""

from __future__ import annotations

from typing import Any

import pytest

from reporails_cli.formatters.mcp import bound_validate_payload
from reporails_cli.formatters.mcp_view import (
    LOCATIONS_BUDGET,
    has_text_view,
    locations_block,
    render_text_view,
    unseen_notices,
)

RULES = {"CORE:C:0001": {"title": "Vague wording", "url": "https://docs.example/c1"}}


def _location(order: int, kind: str = "main", files: list[str] | None = None) -> dict[str, Any]:
    return {
        "order": order,
        "kind": kind,
        "element": f"dir{order}/CLAUDE.md",
        "importance": "gate_mover",
        "finding_count": 12,
        "files": files if files is not None else [f"dir{order}/CLAUDE.md"],
    }


def _paid_payload() -> dict[str, Any]:
    return {
        "tier": "pro",
        "quality": 8.8,
        "level": "L5",
        "stats": {"total_findings": 422},
        "compression": {"findings": 422, "locations": 19, "moves_score": 31, "cosmetic": 287},
        "offline": False,
        "notices": [{"id": "pay", "level": "warn", "text": "Payment failed", "url": "https://pay.example"}],
        "surface_health": [{"name": "Main", "score": 9.1, "file_count": 1, "finding_count": 12}],
        "workflow": {
            "summary": "Rewrite 1 location.",
            "targets": {"tokens": ["@main"], "locations": 1, "of": 4},
            "locations": [_location(1)],
            "listed": [
                {
                    "code": "leave-it",
                    "reason": "Kept as is.",
                    "rules": [{"rule": "CORE:C:0001", "count": 3}, {"rule": "X:1", "count": 1}],
                }
            ],
        },
        "rules": RULES,
        "truncated": {"hint": "Call remedy_brief."},
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_paid_view_renders_every_section_in_order() -> None:
    text = render_text_view(_paid_payload())
    lines = text.split("\n")
    assert lines[0] == "validate: tier pro · score 8.8/10 · 422 findings · level L5 · 1 files"
    assert lines[1] == "compression: 422 findings → 19 rewrites · 31 move your score · 287 cosmetic"
    assert "notices:" in lines and "  - warn: Payment failed (https://pay.example)" in lines
    assert "  - Main · score 9.1 · 12 findings · 1 files" in lines
    assert "workflow.summary: Rewrite 1 location." in lines
    assert "workflow.targets: @main · 1 of 4 locations" in lines
    assert "  1 | main | dir1/CLAUDE.md | gate_mover | 12 | dir1/CLAUDE.md" in lines
    assert "  - code: leave-it" in lines and "    reason: Kept as is." in lines
    assert lines.index("    reason: Kept as is.") == lines.index("  - code: leave-it") + 1
    assert "    rules: Vague wording ([CORE:C:0001](https://docs.example/c1)) \u00d73; X:1 \u00d71" in lines
    assert lines[-1] == "truncated.hint: Call remedy_brief."
    order = [
        text.index(k)
        for k in ("validate:", "compression:", "notices:", "surface_health:", "workflow.summary:", "truncated.hint:")
    ]
    assert order == sorted(order)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_absent_sections_are_left_out() -> None:
    assert render_text_view({"workflow": {"locations": []}}) == ""
    text = render_text_view({"tier": "pro", "workflow": {"summary": "s"}})
    assert text == "validate: tier pro\nworkflow.summary: s"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_offline_server_error_and_funnel_lines() -> None:
    payload = {
        "offline": True,
        "server_error": {"error": "rate_limited", "status": 429, "message": "Slow down"},
        "funnel": {"retryable": True, "retry_after": 10, "message": "Try later"},
    }
    lines = render_text_view(payload).split("\n")
    assert lines[0] == "offline: true"
    assert lines[1] == "server_error: rate_limited · status 429"
    assert lines[2] == "funnel.retryable: true · funnel.retry_after: 10 · Try later"
    only_error = render_text_view({"offline": True, "server_error": {"error": "x", "status": 500, "message": "Down"}})
    assert only_error.split("\n")[0] == "offline: true — Down"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_host_hooks_line() -> None:
    hook = {
        "agent": "claude",
        "event": "PreToolUse",
        "matcher": "Bash",
        "scope": "project",
        "file": ".claude/settings.json",
        "tools": ["Read", "Edit"],
        "identity_fields": [],
    }
    text = render_text_view({"host_hooks": [hook]})
    assert text == (
        "host_hooks:\n  - claude · PreToolUse · matcher Bash · project · .claude/settings.json"
        " · tools Read, Edit · identity none"
    )


@pytest.mark.unit
@pytest.mark.subsys_server
def test_preservation_and_feedback_view() -> None:
    payload = {
        "rules": RULES,
        "preservation": {
            "ok": False,
            "score_before": 7.1,
            "score_after": 8.0,
            "introduced": 3,
            "lost_instructions": [{"line": 4, "text": "Run tests"}],
            "padded_lines": [],
            "removed_structure": {"table_rows": 0, "fences": 0},
            "made_direct": [{"before": "prefer X", "after": "use X"}],
            "kept": {"instructions": 40, "table_rows": 2, "list_items": 9, "headings": 5, "fences": 0, "links": 3},
        },
        "feedback": [
            {
                "rule": "CORE:C:0001",
                "line": 12,
                "message": "Be specific",
                "op": "direct",
                "impact_tier": "gate_mover",
            }
        ],
    }
    lines = render_text_view(payload).split("\n")
    assert lines[0] == "preservation.ok: false · score_before 7.1 · score_after 8.0 · introduced 3"
    assert lines[1] == 'preservation.lost_instructions: [{"line":4,"text":"Run tests"}]'
    assert lines[2] == 'preservation.made_direct: [{"before":"prefer X","after":"use X"}]'
    assert (
        lines[3] == "preservation.kept: instructions 40 · table_rows 2 · list_items 9 · headings 5 · fences 0 · links 3"
    )
    assert not any(line.startswith(("preservation.padded_lines", "preservation.removed_structure")) for line in lines)
    assert lines[4:] == [
        "feedback:",
        "  - gate_mover Vague wording ([CORE:C:0001](https://docs.example/c1)) line 12 — Be specific — op: direct",
    ]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_view_is_deterministic() -> None:
    payload = _paid_payload()
    assert render_text_view(payload) == render_text_view(dict(payload))


@pytest.mark.unit
@pytest.mark.subsys_server
def test_notice_shows_once_per_state() -> None:
    seen: set[str] = set()
    first = unseen_notices(_paid_payload(), seen)
    second = unseen_notices(_paid_payload(), seen)
    assert "notices:" in render_text_view(first)
    assert "notices:" not in render_text_view(second)
    assert second["notices"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_has_text_view_channel_rule() -> None:
    assert has_text_view({"workflow": {}}, full=False)
    assert has_text_view({"preservation": {}}, full=False)
    assert not has_text_view({"workflow": {}}, full=True)
    assert not has_text_view({"tier": "free", "files": {}}, full=False)
    assert not has_text_view({"error": "circuit_breaker"}, full=False)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_locations_block_stays_under_budget_for_sixty_locations() -> None:
    kinds = ["main", "rules", "skills"]
    locations = [_location(i, kinds[i % 3], [f"deep/{'x' * 80}/f{i}_{j}.md" for j in range(5)]) for i in range(1, 61)]
    lines = locations_block(locations)
    assert sum(len(line) + 1 for line in lines) <= LOCATIONS_BUDGET
    assert lines[0].startswith("workflow.locations:")
    rows = [line for line in lines[1:] if " | " in line]
    assert 0 < len(rows) < 60
    assert all("+2 more" in row for row in rows)
    assert rows[0].lstrip().startswith("1 |")
    tail = [line for line in lines if line.endswith("listed in full once earlier rounds re-validate")]
    assert len(tail) == 3
    assert all("locations (orders " in line and "\u2013" in line for line in tail)
    assert sum(int(line.split(": ")[1].split(" ")[0]) for line in tail) == 60 - len(rows)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_locations_block_all_rows_when_they_fit() -> None:
    lines = locations_block([_location(i) for i in range(1, 6)])
    assert len(lines) == 6 and not any("listed in full once" in line for line in lines)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_compression_counts_tiers_over_findings_and_cross_file() -> None:
    payload = {
        "files": {
            "A.md": {
                "count": 3,
                "findings": [{"impact_tier": "gate_mover"}, {"impact_tier": "cosmetic"}, {"rule": "x"}],
            },
            "B.md": {"count": 1, "findings": [{"impact_tier": "conditional"}]},
        },
        "cross_file": [{"file_1": "A.md", "impact_tier": "cosmetic"}],
        "workflow": {"locations": [_location(1), _location(2)]},
    }
    assert bound_validate_payload(payload)["compression"] == {
        "findings": 5,
        "locations": 2,
        "moves_score": 2,
        "cosmetic": 3,
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_compression_reads_the_leverage_a_real_payload_carries_per_file() -> None:
    payload = {
        "files": {"A.md": {"count": 2, "findings": [{"leverage": "gate_mover"}, {"leverage": "cosmetic"}]}},
        "workflow": {"locations": [_location(1)]},
    }
    assert bound_validate_payload(payload)["compression"] == {
        "findings": 2,
        "locations": 1,
        "moves_score": 1,
        "cosmetic": 1,
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_compression_counts_a_finding_in_a_file_and_a_location_once() -> None:
    shared = {"rule": "x", "file": "A.md", "line": 3, "impact_tier": "gate_mover"}
    location = {**_location(1), "findings": [shared]}
    payload = {
        "files": {"A.md": {"count": 1, "findings": [shared]}},
        "workflow": {"locations": [location]},
    }
    assert bound_validate_payload(payload)["compression"] == {
        "findings": 1,
        "locations": 1,
        "moves_score": 1,
        "cosmetic": 0,
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_compression_absent_without_workflow() -> None:
    assert "compression" not in bound_validate_payload({"files": {"A.md": {"count": 1, "findings": [{"rule": "x"}]}}})


@pytest.mark.unit
@pytest.mark.subsys_server
def test_preservation_headline_shows_the_introduced_count_once() -> None:
    lines = render_text_view({"preservation": {"ok": True, "introduced": 3, "kept": {"links": 1}}}).split("\n")
    assert lines == ["preservation.ok: true · introduced 3", "preservation.kept: links 1"]
    assert render_text_view({"preservation": {"ok": True, "introduced": 0}}) == "preservation.ok: true · introduced 0"


def _finding(rule: str, line: int, **extra: Any) -> dict[str, Any]:
    return {
        "rule": rule,
        "file": "dir1/CLAUDE.md",
        "line": line,
        "op": "split",
        "expect": {},
        "impact_tier": "gate_mover",
        "members": [],
        **extra,
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_targeted_view_renders_each_location_s_findings_members_and_relations() -> None:
    member = _finding("CORE:C:0001", 9)
    location = {
        **_location(1),
        "findings": [_finding("CORE:C:0001", 4, members=[member]), _finding("X:2", 7, impact_tier="cosmetic")],
        "relations": [
            {
                "rule": "CORE:C:0001",
                "file": "dir1/CLAUDE.md",
                "line": 3,
                "partner_file": "dir2/CLAUDE.md",
                "partner_line": 11,
                "op": "dedupe",
                "expect": {"keep": ["dir2/CLAUDE.md", 11]},
            }
        ],
    }
    payload = {
        "rules": RULES,
        "workflow": {"targets": {"tokens": ["@main"], "locations": 1, "of": 2}, "locations": [location]},
    }
    lines = render_text_view(payload).split("\n")
    row = lines.index("  1 | main | dir1/CLAUDE.md | gate_mover | 12 | dir1/CLAUDE.md")
    link = "Vague wording ([CORE:C:0001](https://docs.example/c1))"
    assert lines[row + 1 :] == [
        f"      - gate_mover {link} dir1/CLAUDE.md:4 — op: split",
        f"        - gate_mover {link} dir1/CLAUDE.md:9 — op: split",
        "      - cosmetic X:2 dir1/CLAUDE.md:7 — op: split",
        f"      - relation {link} dir1/CLAUDE.md:3 \u2194 dir2/CLAUDE.md:11 — op: dedupe",
    ]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_location_detail_does_not_count_toward_the_table_budget() -> None:
    detailed = [{**_location(i), "findings": [_finding("X:2", 1)] * 50} for i in range(1, 4)]
    plain = [_location(i) for i in range(1, 4)]
    lines = render_text_view({"workflow": {"locations": detailed}}).split("\n")
    assert [line for line in lines if not line.startswith("      ")] == locations_block(plain)
    assert len(lines) > 150
