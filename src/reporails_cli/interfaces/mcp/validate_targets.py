"""`validate` / `remedy_brief` target resolution — the `targets` argument's own surface.

Resolves the `skills`, `skills:<name>`, `agents:<name>`, `@main`, path tokens `targets` carries
into the files and directories they name, and narrows a `validate` payload down to the
locations, files, and cross-file entries that hold one of them.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from reporails_cli.core.classify.capability_paths import TargetError
from reporails_cli.core.classify.focus_expansion import resolve_capability_spec
from reporails_cli.core.discovery.agents import detect_agents
from reporails_cli.core.discovery.exclusions import load_run_exclusions
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.lint.suppression import renumbered_json
from reporails_cli.core.pipeline.mapping import resolve_agent_filters
from reporails_cli.core.pipeline.named_targets import markdown_under_folders, read_targets, target_report
from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_list, as_object, as_str, str_list
from reporails_cli.core.platform.dto.discovery import RunExclusions
from reporails_cli.core.platform.dto.targets import TargetReading, TargetReport
from reporails_cli.interfaces.mcp.remedy_brief import resolve_from_root


def target_tokens(targets: list[str] | None) -> tuple[str, ...]:
    """The distinct non-empty target tokens, sorted — one spelling per set of targets."""
    return tuple(sorted({t.strip() for t in targets or () if t and t.strip()}))


def named_files(selection: tuple[set[Path], set[Path]] | None) -> frozenset[Path]:
    """The files a resolved target selection names directly (none for no selection)."""
    return frozenset(selection[0]) if selection is not None else frozenset()


def _target_context(run: RunContext, scan_root: Path) -> tuple[RunExclusions, str]:
    """The `(exclusions, effective agent)` that read the target tokens under `scan_root`."""
    exclusions = load_run_exclusions(run, scan_root)
    effective_agent, _, _, _ = resolve_agent_filters(
        run,
        run.project_config(scan_root).default_agent,
        detect_agents(run, scan_root),
        scan_root,
        exclusions,
    )
    return exclusions, effective_agent


def read_validate_targets(run: RunContext, tokens: tuple[str, ...], scan_root: Path) -> TargetReading:
    """`tokens` read the way `ails check` reads its targets, a relative path against `scan_root`."""
    return read_targets(run, tokens, "", scan_root, base=scan_root)


def validate_target_report(
    run: RunContext, tokens: tuple[str, ...], scan_root: Path, checked: list[Path]
) -> TargetReport:
    """The targets among `tokens` that none of the `checked` files came from, each with its reason."""
    exclusions, effective_agent = _target_context(run, scan_root)
    return target_report(
        run,
        read_validate_targets(run, tokens, scan_root),
        checked,
        exclusions=exclusions,
        effective_agent=effective_agent,
        project_root=scan_root,
    )


def _capability_files(
    run: RunContext,
    specs: Sequence[tuple[str, str]],
    effective_agent: str,
    scan_root: Path,
    exclusions: RunExclusions,
) -> tuple[set[Path], set[Path]] | JsonObject:
    """The files and skill folders the capability `specs` name, or a `target_not_found` error payload."""
    files: set[Path] = set()
    dirs: set[Path] = set()
    for capability, name in specs:
        try:
            paths, _unresolved = resolve_capability_spec(
                run, capability, name, effective_agent, project_root=scan_root, exclusions=exclusions
            )
        except TargetError as err:
            return {"error": "target_not_found", "message": err.message()}
        resolved_paths = {safe_resolve(p) for p in paths}
        files |= resolved_paths
        # A skill names its whole folder (references and the rest); an agent or rule is its one file.
        dirs |= {p.parent for p in resolved_paths if p.name == "SKILL.md"}
    return files, dirs


def resolve_validate_targets(
    run: RunContext, tokens: tuple[str, ...], scan_root: Path
) -> tuple[set[Path], set[Path]] | JsonObject:
    """The files and directories `tokens` name under `scan_root`, read the way `ails check` reads
    its targets (`skills`, `skills:<name>`, `agents:<name>`, `@main`, a path; a typed word such
    as `skill` reads as its config key). A relative path is read against `scan_root`. The markdown
    under a named folder is named too, as `ails check` checks it. A capability the agent lacks
    names nothing (the report lists it). Returns `(files, dirs)` — every path resolved — or a
    `target_not_found` error payload."""

    exclusions, effective_agent = _target_context(run, scan_root)
    reading = read_validate_targets(run, tokens, scan_root)
    if reading.missing:
        return {"error": "target_not_found", "message": f"Path not found: {reading.missing[0].path}"}
    named = _capability_files(run, reading.capability_specs, effective_agent, scan_root, exclusions)
    if isinstance(named, dict):
        return named
    files, dirs = named
    folders = [p for p in reading.path_targets if p.is_dir() and p != scan_root]
    for path in reading.path_targets:
        if path.is_dir():
            dirs.add(safe_resolve(path))
        else:
            files.add(safe_resolve(path))
    files |= {safe_resolve(f) for f in markdown_under_folders(folders, exclusions)}
    return files, dirs


def keep_target_locations(
    payload: JsonObject, files: set[Path], dirs: set[Path], scan_root: Path, tokens: tuple[str, ...]
) -> JsonObject:
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

    def targeted(rel: str) -> bool:
        path = resolve_from_root(rel, scan_root)
        return path in files or any(path.is_relative_to(d) for d in dirs)

    workflow = payload.get("workflow")
    kept: list[JsonObject] = []
    locations: list[JsonObject] = []
    if isinstance(workflow, dict):
        locations = [loc for loc in as_list(workflow.get("locations")) if isinstance(loc, dict)]
        kept = [loc for loc in locations if any(targeted(f) for f in str_list(loc.get("files")))]

    kept_files = {f for loc in kept for f in str_list(loc.get("files"))}

    def keeps(rel: str) -> bool:
        return targeted(rel) or rel in kept_files

    def keeps_pair(pairs: list[JsonValue]) -> list[JsonValue]:
        return [
            p
            for p in pairs
            if isinstance(p, dict) and (keeps(as_str(p.get("file_1"))) or keeps(as_str(p.get("file_2"))))
        ]

    out = dict(payload)
    if isinstance(payload.get("files"), dict):
        out["files"] = {rel: entry for rel, entry in as_object(payload["files"]).items() if keeps(rel)}
    for key in ("cross_file", "cross_file_coordinates"):
        if isinstance(payload.get(key), list):
            out[key] = keeps_pair(as_list(payload[key]))

    if not isinstance(workflow, dict):
        return out

    out["workflow"] = {
        **workflow,
        "locations": [*renumbered_json(kept)],
        "targets": {"tokens": [*tokens], "locations": len(kept), "of": len(locations)},
    }
    return out
