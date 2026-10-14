"""Narrow a combined result and ruleset map to a subset of paths.

Used when a run is scoped to a capability or a path set: findings, cross-file pairs,
per-file analysis, the headline score and the mapped files all follow the same subset.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace as _replace
from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.platform.runtime.merger import (
    CombinedStats,
    count_cross_file_overlaps,
    count_cross_file_repetitions,
    normalize_finding_path,
)
from reporails_cli.formatters.text.health import mean_display_score


def filter_result_to_paths(result: Any, paths: set[Path], project_root: Path) -> Any:
    """Return a CombinedResult containing only rows for `paths`.

    Filters findings, cross-file pairs, per-file analysis, AND the
    aggregate quality — without filtering it, the top score uses the
    whole project while surface-health uses the filtered files and the
    two scores disagree.
    """

    def _in_scope(path: str) -> bool:
        # `findings` are already project-relative; server `per_file` / `cross_file`
        # carry absolute paths, so normalize before the membership test.
        return normalize_finding_path(path, project_root) in rel_keys

    # Normalize keys through the same function as findings so out-of-tree
    # targets (e.g. `~/.claude/...` memory) match — `_relativize` falls back to
    # the absolute path while `normalize_finding_path` yields the `~/` form.
    rel_keys = {normalize_finding_path(str(p), project_root) for p in paths}
    findings = tuple(f for f in result.findings if _in_scope(f.file))
    cross = tuple(cf for cf in result.cross_file if _in_scope(cf.file_1) or _in_scope(cf.file_2))
    # The aggregate form is scoped by the same rule, so the narrowed view's
    # repetition and overlap counts match its narrowed pair list at every tier.
    coords = tuple(c for c in result.cross_file_coordinates if _in_scope(c.file_1) or _in_scope(c.file_2))
    per_file = tuple(fa for fa in result.per_file_analysis if _in_scope(fa.file))
    unfinished = tuple(pair for pair in result.omissions.not_evaluated if _in_scope(pair[1]))
    sev = Counter(f.severity for f in findings)
    stats = CombinedStats(
        total_findings=len(findings),
        errors=sev.get("error", 0),
        warnings=sev.get("warning", 0),
        infos=sev.get("info", 0),
        cross_file_repetitions=count_cross_file_repetitions(cross, coords),
        cross_file_overlaps=count_cross_file_overlaps(cross, coords),
        m_probe_count=result.stats.m_probe_count,
        client_check_count=result.stats.client_check_count,
        server_diagnostic_count=result.stats.server_diagnostic_count,
    )
    quality = _filter_quality(result.quality, per_file)
    return _replace(
        result,
        findings=findings,
        cross_file=cross,
        cross_file_coordinates=coords,
        stats=stats,
        per_file_analysis=per_file,
        quality=quality,
        omissions=_replace(result.omissions, not_evaluated=unfinished),
    )


def _filter_quality(quality: Any, per_file: tuple[Any, ...]) -> Any:
    """Rewrite the aggregate display score from the filtered per-file set.

    The whole-project `display_score` covers every file; once
    the view is narrowed to a subset (e.g. `ails check skills`) there is no
    aggregate for that subset, so the headline becomes the mean of the subset's
    per-file display scores — matching the per-surface/per-item bars.
    """
    if quality is None:
        return None

    if not any(int(fa.stats.get("atoms", 0) or 0) > 0 for fa in per_file):
        return None
    # All-unscored subset (every file has a None score) → fall back to the reported
    # whole-project aggregate, which itself may be `None` when the whole project has
    # no scorable content — the renderer treats that as "n/a", never as a fabricated
    # score, so passing `None` through here is correct, not a missed case.
    mean_score = mean_display_score(list(per_file)) if per_file else quality.display_score
    if mean_score is None:
        mean_score = quality.display_score
    return _replace(quality, display_score=mean_score)


def filter_ruleset_map_to_paths(ruleset_map: Any, paths: set[Path], project_root: Path) -> Any:
    """Return a RulesetMap restricted to `paths` (matching files + their atoms)."""
    if ruleset_map is None or not paths:
        return ruleset_map
    keep = {_relativize(p, project_root).as_posix() for p in paths} | {p.as_posix() for p in paths}
    files = tuple(fr for fr in ruleset_map.files if fr.path in keep)
    atoms = tuple(a for a in ruleset_map.atoms if a.file_path in keep)
    # RulesetMap/RulesetSummary are Pydantic models; dataclasses.replace
    # raises TypeError on a BaseModel, so use model_copy for the Pydantic target.
    return ruleset_map.model_copy(update={"files": files, "atoms": atoms})


def _relativize(path: Path, project_root: Path) -> Path:
    """Return `path` relative to `project_root` without resolving symlinks.

    Symlinks may point outside the project (e.g. symlinked skills);
    resolving would push the path outside `project_root` and force the
    fallback. Use textual prefix stripping instead.
    """
    try:
        return path.relative_to(project_root)
    except ValueError:
        pass
    try:
        return safe_resolve(Path(path)).relative_to(safe_resolve(project_root))
    except ValueError:
        return path
