"""`-f json` / `--format github` trailing JSON emit canonical rule IDs.

A bare client-check token (`format`, `orphan`, …) is canonicalized to
`<NS>:<CAT>:<SLOT>` on the wire, with the raw token preserved under `label`
for baseline stability. Already-canonical server IDs pass through untouched.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.runtime.merger import CombinedResult, CombinedStats, FindingItem
from reporails_cli.formatters.json import format_combined_result


def _result(*findings: FindingItem) -> CombinedResult:
    return CombinedResult(
        findings=tuple(findings),
        cross_file=(),
        quality=None,
        per_file_analysis=(),
        stats=CombinedStats(total_findings=len(findings), errors=0, warnings=len(findings), infos=0),
        offline=True,
        hints=(),
        cross_file_coordinates=(),
    )


def _finding(rule: str) -> FindingItem:
    return FindingItem(file="CLAUDE.md", line=1, severity="warning", rule=rule, message="m")


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_canonical_id_passes_through_without_label() -> None:
    data = format_combined_result(_result(_finding("CORE:C:0042")))
    entry = data["files"]["CLAUDE.md"]["findings"][0]
    assert entry["rule"] == "CORE:C:0042"
    assert "label" not in entry


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_top_rules_uses_canonical_ids() -> None:
    data = format_combined_result(_result(_finding("format"), _finding("format")))
    top = data["top_rules"]
    assert top[0]["rule"] == "CORE:E:0003"
    assert top[0]["count"] == 2
