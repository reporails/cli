"""The findings of a check, counted per file."""

from __future__ import annotations

from collections.abc import Iterable
from typing import get_args

from reporails_cli.core.pipeline.check_one import CheckRun
from reporails_cli.core.platform.dto.diagnostics import FindingItem, FindingSeverity
from reporails_cli.core.platform.dto.xray import FindingTally
from reporails_cli.core.platform.runtime.merger import normalize_finding_path


def tally_of(findings: Iterable[FindingItem]) -> FindingTally:
    """The count of `findings` and the count of each severity."""
    by_severity: dict[FindingSeverity, int] = dict.fromkeys(get_args(FindingSeverity), 0)
    total = 0
    for finding in findings:
        by_severity[finding.severity] += 1
        total += 1
    return FindingTally(total, by_severity)


def tallies_by_file(run: CheckRun) -> dict[str, FindingTally]:
    """The tally of every file a run checked, keyed by its project-relative path; a file with no finding holds a
    zero tally."""
    root = run.scope.scan_root
    grouped: dict[str, list[FindingItem]] = {
        normalize_finding_path(str(path), root): [] for path in run.scope.instruction_files
    }
    for finding in run.result.findings:
        grouped.setdefault(normalize_finding_path(finding.file, root), []).append(finding)
    return {key: tally_of(items) for key, items in grouped.items()}
