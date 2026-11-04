"""The findings of a check, counted per file."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.diagnostics import FindingItem
from reporails_cli.core.platform.dto.pipeline import CheckRun
from reporails_cli.core.platform.dto.xray_sources import FindingTally
from reporails_cli.core.platform.runtime.merger import normalize_finding_path, severity_counts


def tally_of(findings: Sequence[FindingItem]) -> FindingTally:
    """The count of `findings` and the count of each severity."""
    return FindingTally(len(findings), severity_counts(findings))


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
