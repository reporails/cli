"""Focus filters for capability-mode `ails check`.

Capability mode (`ails check <capability> [<name>]`) reuses the standard
whole-repo renderer (`print_text_result`); these helpers narrow the
`CombinedResult` and `RulesetMap` to the focused subset of files so the
rendered output has the same shape with fewer rows.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any


def filter_result_to_focus(result: Any, focus_paths: set[Path], project_root: Path) -> Any:
    """Return a CombinedResult restricted to the rows in `focus_paths`.

    Filters findings, cross-file pairs, and per-file analysis so the
    standard renderer's surface-health / file-card / scorecard blocks
    all reflect the same subset.
    """
    from dataclasses import replace as _replace

    from reporails_cli.core.platform.runtime.merger import CombinedStats

    rel_keys = {str(_to_rel(p, project_root)) for p in focus_paths}
    filtered_findings = tuple(f for f in result.findings if f.file in rel_keys)
    filtered_cross = tuple(cf for cf in result.cross_file if cf.file_1 in rel_keys or cf.file_2 in rel_keys)
    filtered_per_file = tuple(fa for fa in result.per_file_analysis if fa.file in rel_keys)
    severity_counts = Counter(f.severity for f in filtered_findings)
    stats = CombinedStats(
        total_findings=len(filtered_findings),
        errors=severity_counts.get("error", 0),
        warnings=severity_counts.get("warning", 0),
        infos=severity_counts.get("info", 0),
        cross_file_conflicts=sum(1 for c in filtered_cross if c.finding_type == "conflict"),
        cross_file_repetitions=sum(1 for c in filtered_cross if c.finding_type == "repetition"),
        m_probe_count=result.stats.m_probe_count,
        client_check_count=result.stats.client_check_count,
        server_diagnostic_count=result.stats.server_diagnostic_count,
    )
    return _replace(
        result,
        findings=filtered_findings,
        cross_file=filtered_cross,
        stats=stats,
        per_file_analysis=filtered_per_file,
    )


def filter_ruleset_map_to_paths(ruleset_map: Any, focus_paths: set[Path], project_root: Path) -> Any:
    """Return a RulesetMap restricted to `focus_paths` (matching files + their atoms)."""
    from dataclasses import replace as _replace

    if ruleset_map is None or not focus_paths:
        return ruleset_map
    rel_keys = {str(_to_rel(p, project_root)) for p in focus_paths}
    abs_keys = {str(p) for p in focus_paths}
    keep = rel_keys | abs_keys
    filtered_files = tuple(fr for fr in ruleset_map.files if str(fr.path) in keep)
    filtered_atoms = tuple(a for a in ruleset_map.atoms if a.file_path in keep)
    return _replace(ruleset_map, files=filtered_files, atoms=filtered_atoms)


def _to_rel(path: Path, project_root: Path) -> Path:
    """Return path relative to project_root WITHOUT resolving symlinks.

    Symlinks may point outside the project (e.g. hub-symlinked skills);
    resolving would push the path outside `project_root` and force the
    fallback. Use textual prefix stripping instead.
    """
    try:
        return path.relative_to(project_root)
    except ValueError:
        pass
    try:
        return Path(path).resolve().relative_to(project_root.resolve())
    except ValueError:
        return path
