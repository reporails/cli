"""File grouping for text output: which card group a file belongs to, and the per-file indexes
(hints, regimes, aliases) the cards read."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from reporails_cli.formatters.text.display_constants import SEV_WEIGHT, path_tag


def group_key(filepath: str, ft: dict[str, str], root: Path, skill_of: dict[str, str] | None) -> str:
    """File-group key for a path: `skills` for a file inside a skill folder first, then `imported` /
    `referenced` by classifier type, else the path-based tag (a `SKILL.md` outside every skill
    folder is a plain file whenever a skill lookup exists)."""
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    norm = normalize_finding_path(filepath, root)
    if skill_of is not None and norm in skill_of:
        return "skills"
    file_type = ft.get(norm, "")
    if file_type in ("generic", "referenced"):
        return "imported" if file_type == "generic" else "referenced"
    return path_tag(filepath, skill_of, norm).split(":")[0]


def build_file_groups(
    result: Any,
    file_type_by_path: dict[str, str] | None = None,
    project_root: Path | None = None,
    skill_of: dict[str, str] | None = None,
    aliases_by_file: dict[str, list[str]] | None = None,
) -> dict[str, list[tuple[str, list[Any]]]]:
    """Group findings by file type, sorted worst-first within each group.

    A file that is an alias of another (`aliases_by_file`) has no card of its own: its findings
    join the canonical file's card, a finding both carry (same line, rule and message) once.

    Generic-scanned files route by classifier `file_type`: `@`-import (`generic`) → the
    `imported` group, markdown-link (`referenced`) → the `referenced` group. Everything else
    falls back to the path-based `classify_file` tag; a file inside a skill folder (`skill_of`)
    goes to the `skills` group.
    """
    ft = file_type_by_path or {}
    root = project_root or Path.cwd()
    by_file: dict[str, list[Any]] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)
    by_file = _fold_alias_items(by_file, aliases_by_file, lambda f: (f.line, f.rule, f.message))

    groups: dict[str, list[tuple[str, list[Any]]]] = {}
    for filepath, findings in by_file.items():
        if filepath in (".", ".:0"):
            continue
        key = group_key(filepath, ft, root, skill_of)
        groups.setdefault(key, []).append((filepath, findings))

    for group_files in groups.values():
        group_files.sort(key=lambda x: (min(SEV_WEIGHT.get(f.severity, 9) for f in x[1]), -len(x[1])))

    return groups


def _fold_alias_items(
    by_file: dict[str, list[Any]],
    aliases_by_file: dict[str, list[str]] | None,
    identity: Callable[[Any], tuple[Any, ...]],
) -> dict[str, list[Any]]:
    """Move each alias file's items under its canonical file, dropping an item the canonical already holds.

    `identity` names what makes two items the same (a finding by line, rule and message). Items
    an alias alone holds stay, so nothing a file reports is lost by folding it.
    """
    canonical_of = {alias: canonical for canonical, aliases in (aliases_by_file or {}).items() for alias in aliases}
    if not canonical_of.keys() & by_file.keys():
        return by_file
    folded: dict[str, list[Any]] = {}
    seen: dict[str, set[tuple[Any, ...]]] = {}
    # Canonical files first, so an alias item is the one dropped when both carry it.
    for path in sorted(by_file, key=lambda p: p in canonical_of):
        target = canonical_of.get(path, path)
        bucket, keys = folded.setdefault(target, []), seen.setdefault(target, set())
        for item in by_file[path]:
            key = identity(item)
            if target != path and key in keys:
                continue
            keys.add(key)
            bucket.append(item)
    return folded


def build_hints_by_file(
    hints: Any, project_root: Path, aliases_by_file: dict[str, list[str]] | None = None
) -> dict[str, list[Any]]:
    """Build a file-keyed index of hints for inline display; an alias file's hints fold into its canonical's."""
    result: dict[str, list[Any]] = {}
    if hints:
        from reporails_cli.core.platform.runtime.merger import normalize_finding_path

        for h in hints:
            norm = normalize_finding_path(h.file, project_root)
            result.setdefault(norm, []).append(h)
    return _fold_alias_items(
        result,
        aliases_by_file,
        lambda h: (h.diagnostic_type, h.count, h.severity, h.error_count, h.warning_count),
    )


def build_regime_by_file(result: Any, project_root: Path) -> dict[str, Any]:
    """Build a file-keyed index of per-file regimes from server analysis stats.

    Empty for offline runs (no `per_file_analysis`) — callers then render the
    neutral findings view.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path
    from reporails_cli.formatters.triage import classify_regime

    regimes: dict[str, Any] = {}
    for fa in result.per_file_analysis:
        regime = classify_regime(fa.stats)
        if regime is not None:
            regimes[normalize_finding_path(fa.file, project_root)] = regime
    return regimes


def build_aliases_by_file(project_root: Path, result: Any) -> dict[str, list[str]]:
    """Combine discovery-time symlink aliases with display-time same-dir content aliases.

    `get_file_aliases` returns paths the discovery layer already collapsed
    (symlinks to one inode). `compute_same_dir_content_aliases` runs against
    the union of files referenced by findings — catches manual AGENTS.md /
    CLAUDE.md pairs that classify under different agents but should render as
    one row. Both alias sources are returned as project-relative posix strings
    so `_print_file_card` can do a plain dict lookup.
    """
    from reporails_cli.core.discovery.file_aliases import compute_same_dir_content_aliases, get_file_aliases
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    out: dict[str, list[str]] = {}
    for canonical, alias_paths in get_file_aliases(project_root).items():
        key = normalize_finding_path(str(canonical), project_root)
        values = [normalize_finding_path(str(a), project_root) for a in alias_paths]
        if values:
            out[key] = values

    finding_paths: set[Path] = set()
    if result.findings:
        for f in result.findings:
            p = Path(f.file)
            finding_paths.add(p if p.is_absolute() else (project_root / p))
    for canonical, alias_paths in compute_same_dir_content_aliases(finding_paths).items():
        key = normalize_finding_path(str(canonical), project_root)
        values = [normalize_finding_path(str(a), project_root) for a in alias_paths]
        if values:
            out.setdefault(key, []).extend(values)
    return out
