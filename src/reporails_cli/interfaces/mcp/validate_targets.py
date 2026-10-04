"""`validate` / `remedy_brief` target resolution — the `targets` argument's own surface.

Resolves the `skills`, `skills:<name>`, `agents:<name>`, `@main`, path tokens `targets` carries
into the files and directories they name, and narrows a `validate` payload down to the
locations, files, and cross-file entries that hold one of them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.walk import safe_resolve


def _resolve_one_target(
    token: str, token_agent: str, scan_root: Path, effective_agent: str, exclude_dirs: Any
) -> tuple[set[Path], set[Path]] | dict[str, Any]:
    """One target `token` resolved to the `(files, dirs)` it contributes, or a
    `target_not_found` error payload."""
    from reporails_cli.core.classify.capability_paths import TargetError, classify_target_token, resolve_capability_spec

    kind, target = classify_target_token(token, token_agent, scan_root, base=scan_root)
    if kind == "capability" and isinstance(target, tuple):
        capability, name = target
        try:
            paths, _unresolved = resolve_capability_spec(capability, name, effective_agent, scan_root, exclude_dirs)
        except TargetError as err:
            return {"error": "target_not_found", "message": err.message()}
        return {safe_resolve(p) for p in paths}, set()
    if isinstance(target, Path):
        if not target.exists():
            return {"error": "target_not_found", "message": f"Path not found: {target}"}
        resolved = safe_resolve(target)
        return (set(), {resolved}) if target.is_dir() else ({resolved}, set())
    return set(), set()


def resolve_validate_targets(tokens: tuple[str, ...], scan_root: Path) -> tuple[set[Path], set[Path]] | dict[str, Any]:
    """The files and directories `tokens` name under `scan_root`, read the way `ails check` reads
    its targets (`skills`, `skills:<name>`, `agents:<name>`, `@main`, a path; a typed word such
    as `skill` reads as its config key). A relative path is read against `scan_root`. Returns
    `(files, dirs)` — every path resolved — or a `target_not_found` error payload."""
    from reporails_cli.core.classify.capability_paths import sniff_agent
    from reporails_cli.core.discovery.agents import detect_agents
    from reporails_cli.core.pipeline.mapping import resolve_agent_filters
    from reporails_cli.core.platform.config.config import get_project_config

    config = get_project_config(scan_root)
    effective_agent, _, _, _ = resolve_agent_filters(
        config.default_agent, detect_agents(scan_root), scan_root, config.exclude_dirs, config.exclude_files
    )
    token_agent = sniff_agent("", scan_root)
    files: set[Path] = set()
    dirs: set[Path] = set()
    for token in tokens:
        result = _resolve_one_target(token, token_agent, scan_root, effective_agent, config.exclude_dirs)
        if isinstance(result, dict):
            return result
        new_files, new_dirs = result
        files |= new_files
        dirs |= new_dirs
    return files, dirs


def keep_target_locations(
    payload: dict[str, Any], files: set[Path], dirs: set[Path], scan_root: Path, tokens: tuple[str, ...]
) -> dict[str, Any]:
    """`payload` narrowed to a targeted file (a file in `files`, or under one of `dirs`):
    `files` keeps only the entries keyed by a targeted path, and `cross_file` and
    `cross_file_coordinates` only the entries where either side is targeted — whether or not
    `workflow` is present (a free-tier reply has none). When `workflow` is present, a location
    is targeted if any one of its own `files` is targeted, and once kept, `files` /
    `cross_file` / `cross_file_coordinates` are narrowed on the union of the targeted files and
    every kept location's own `files` — so a kept location's other files (a skill's
    non-`SKILL.md` files, say) survive alongside the file that got it targeted. With no
    `workflow`, the narrowing uses the targeted files alone. A `workflow` dict also gets
    `locations` narrowed the same way, re-numbered from 1, with `workflow.targets` recording
    the tokens and how many locations they keep. Everything else — `listed`, `pro` (a
    whole-project aggregate, not a per-file/per-pair breakdown), the stats and scores — stays
    whole-project."""
    from reporails_cli.core.lint.suppression import renumbered
    from reporails_cli.interfaces.mcp.remedy_brief import resolve_from_root

    def targeted(rel: str) -> bool:
        path = resolve_from_root(rel, scan_root)
        return path in files or any(path.is_relative_to(d) for d in dirs)

    workflow = payload.get("workflow")
    kept: list[dict[str, Any]] = []
    locations: list[dict[str, Any]] = []
    if isinstance(workflow, dict):
        locations = [loc for loc in workflow.get("locations") or () if isinstance(loc, dict)]
        kept = [loc for loc in locations if any(targeted(f) for f in loc.get("files") or ())]

    kept_files = {f for loc in kept for f in loc.get("files") or ()}

    def keeps(rel: str) -> bool:
        return targeted(rel) or rel in kept_files

    def keeps_pair(pairs: Any) -> list[Any]:
        return [p for p in pairs if keeps(p.get("file_1", "")) or keeps(p.get("file_2", ""))]

    out = dict(payload)
    if isinstance(payload.get("files"), dict):
        out["files"] = {rel: entry for rel, entry in payload["files"].items() if keeps(rel)}
    if isinstance(payload.get("cross_file"), list):
        out["cross_file"] = keeps_pair(payload["cross_file"])
    if isinstance(payload.get("cross_file_coordinates"), list):
        out["cross_file_coordinates"] = keeps_pair(payload["cross_file_coordinates"])

    if not isinstance(workflow, dict):
        return out

    out["workflow"] = {
        **workflow,
        "locations": renumbered(kept),
        "targets": {"tokens": list(tokens), "locations": len(kept), "of": len(locations)},
    }
    return out
