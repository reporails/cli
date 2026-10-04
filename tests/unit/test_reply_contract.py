"""The diagnostics reply: fields the client never reads change nothing it renders."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from reporails_cli.core.platform.adapters.api_client import _deserialize_lint_result
from reporails_cli.core.platform.adapters.payload import local_entries, project_payload
from reporails_cli.core.platform.dto.diagnostics import RulesetReport
from reporails_cli.core.platform.dto.models import LocalEntry
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.runtime.merger import CombinedResult, FindingItem, merge_results
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters import mcp as mcp_formatter
from reporails_cli.formatters.text import display

_FILE = "CLAUDE.md"


def _reply(tier: str = "pro", impact_tier: str = "gate_mover") -> dict[str, Any]:
    """A synthetic reply that carries fields the client reads and fields it ignores."""
    return {
        "tier": tier,
        "report": {
            "per_file": [
                {
                    "file": _FILE,
                    "compliance_band": "MODERATE",
                    "display_score": 6.4,
                    "stats": {
                        "atoms": 4,
                        "triage_tier": "partial",
                        "extra_a": 3,
                        "extra_b": 1,
                        "hedged": 1,
                        "conflicts": 0,
                    },
                    "diagnostics": [
                        {
                            "file": _FILE,
                            "line": 3,
                            "line_2": 0,
                            "severity": "warning",
                            "rule": "CORE:C:0042",
                            "message": "placeholder diagnosis",
                            "fix": "placeholder remedy",
                            "impact_tier": impact_tier,
                            "pi": 2,
                        }
                    ],
                }
            ],
            "cross_file": [
                {
                    "file_1": _FILE,
                    "file_2": "rules/a.md",
                    "line_1": 3,
                    "line_2": 5,
                    "charge_1": 1,
                    "charge_2": 1,
                    "topicality": "near",
                    "extra_d": 1,
                    "extra_e": 2,
                    "finding_type": "repetition",
                }
            ],
            "quality": {
                "display_score": 6.4,
                "compliance_band": "MODERATE",
                "weakest_context": "base",
                "strongest_context": "base",
                "contexts": [
                    {
                        "context_name": "base",
                        "files": [_FILE],
                        "compliance_band": "MODERATE",
                        "n_charged": 3,
                        "n_atoms": 4,
                        "per_target": [
                            {
                                "line": 3,
                                "file_path": _FILE,
                                "compliance_band": "LOW",
                                "impact_rank": 1,
                                "capacity": "low",
                            }
                        ],
                    }
                ],
            },
            "stats": {"files": 1, "extra_c": 0, "cross_file_conflicts": 0},
        },
        "hints": [
            {
                "file": _FILE,
                "diagnostic_type": "CORE:C:0044",
                "count": 2,
                "summary": "placeholder summary",
                "severity": "warning",
                "error_count": 0,
                "warning_count": 2,
            }
        ],
        "cross_file_coordinates": [{"file_1": _FILE, "file_2": "rules/b.md", "finding_type": "overlap", "count": 1}],
    }


def _stripped(reply: dict[str, Any]) -> dict[str, Any]:
    """The same reply with every field the client ignores removed."""
    out = copy.deepcopy(reply)
    report = out["report"]
    del report["stats"]
    report["quality"] = {"display_score": report["quality"]["display_score"]}
    for fa in report["per_file"]:
        del fa["compliance_band"]
        fa["stats"] = {"atoms": fa["stats"]["atoms"], "triage_tier": fa["stats"]["triage_tier"]}
        for d in fa["diagnostics"]:
            del d["line_2"]
    for cf in report["cross_file"]:
        for key in ("charge_1", "charge_2", "topicality", "extra_d", "extra_e"):
            del cf[key]
    for h in out["hints"]:
        del h["summary"]
    return out


def _combined(reply: dict[str, Any]) -> CombinedResult:
    lint = _deserialize_lint_result(reply)
    return merge_results(
        [],
        [],
        lint.report,
        hints=lint.hints,
        cross_file_coordinates=lint.cross_file_coordinates,
        project_root=Path("/proj"),
        tier=lint.tier,
    )


def _text(result: CombinedResult, root: Path) -> str:
    with display.console.capture() as cap:
        display.print_text_result(result, elapsed_ms=0, ascii_mode=True, verbose=True, project_root=root)
    return cap.get()


def _json(result: CombinedResult, root: Path) -> str:
    return json.dumps(json_formatter.format_combined_result(result, project_root=root), sort_keys=True)


def _mcp(result: CombinedResult, root: Path) -> str:
    payload = json_formatter.format_combined_result(result, project_root=root)
    return json.dumps(mcp_formatter.bound_validate_payload(payload), sort_keys=True)


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize("tier", ["pro", "anonymous"])
def test_dropped_reply_fields_change_no_output(tier: str, tmp_path: Path) -> None:
    full = _reply(tier=tier)
    lean = _stripped(full)
    a, b = _combined(full), _combined(lean)
    assert _text(a, tmp_path) == _text(b, tmp_path)
    assert _json(a, tmp_path) == _json(b, tmp_path)
    assert _mcp(a, tmp_path) == _mcp(b, tmp_path)


@pytest.mark.unit
@pytest.mark.subsys_api
def test_hints_and_cross_file_rows_survive_without_the_dropped_fields() -> None:
    result = _deserialize_lint_result(_stripped(_reply()))
    assert [h.diagnostic_type for h in result.hints] == ["CORE:C:0044"]
    assert [(c.file_1, c.file_2, c.finding_type) for c in result.report.cross_file] == [
        (_FILE, "rules/a.md", "repetition")
    ]


def _banner(result: CombinedResult, root: Path) -> str:
    return "\n".join(line for line in _text(result, root).splitlines() if "tier" in line.lower() or "Pro" in line)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_quality_presence_reads_the_same_in_every_state(tmp_path: Path) -> None:
    def reply(quality: Any) -> dict[str, Any]:
        r = _stripped(_reply(tier=""))
        r["hints"] = []
        if quality is None:
            del r["report"]["quality"]
        else:
            r["report"]["quality"] = quality
        return r

    normal = _combined(reply({"display_score": 6.4}))
    unscorable = _combined(reply({"display_score": None}))
    missing_report = _combined({"tier": ""})
    offline = merge_results([], [], None, project_root=Path("/proj"))

    # With no tier named, a present quality block reads as an entitled run and an absent one does not.
    assert normal.quality is not None and unscorable.quality is not None
    assert missing_report.quality is None and offline.quality is None
    assert "Pro" in _banner(normal, tmp_path)
    assert "Pro" in _banner(unscorable, tmp_path)
    assert "Pro" not in _banner(missing_report, tmp_path)
    assert offline.offline and "offline" in _text(offline, tmp_path).lower()
    assert isinstance(_deserialize_lint_result({"tier": ""}).report, RulesetReport)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_blank_impact_tier_carries_no_leverage_key(tmp_path: Path) -> None:
    result = _combined(_stripped(_reply(tier="anonymous", impact_tier="")))
    data = json_formatter.format_combined_result(result, project_root=tmp_path)
    finding = data["files"][_FILE]["findings"][0]
    assert "leverage" not in finding
    assert _text(result, tmp_path)


@pytest.mark.unit
@pytest.mark.subsys_api
def test_request_carries_no_summary() -> None:
    ruleset_map = RulesetMap(schema_version="4", embedding_model="m", generated_at="t", files=(), atoms=())
    payload = project_payload(ruleset_map, Path("/proj"))
    assert "summary" not in payload


@pytest.mark.unit
@pytest.mark.subsys_api
def test_local_findings_carry_only_registry_rule_ids() -> None:
    findings = [
        FindingItem(file="a.md", line=1, severity="error", rule="CORE:C:0034", message="m"),
        FindingItem(file="a.md", line=2, severity="error", rule="memory_frontmatter", message="m"),
    ]
    entries: list[LocalEntry] = local_entries(findings, frozenset(), frozenset({"CORE:C:0034"}), lambda rel: rel)
    assert [e.rule for e in entries] == ["CORE:C:0034"]
