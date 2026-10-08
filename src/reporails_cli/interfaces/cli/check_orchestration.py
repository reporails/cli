"""Orchestration helpers for the ``ails check`` command.

Capability-target error reporting (over the core resolver),
output dispatch, the heal pass, strict-exit policy, and the in-process mapper
fallback — the machinery ``check()`` drives. Split out of ``main.py`` so the
command body reads as a flow over named helpers rather than one long function.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import typer

from reporails_cli.core.discovery.agent_discovery import (
    agent_dir_names,
    resolve_project_root_for_file,
    root_markers,
    user_level_agent_dir,
)
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.formatters.text.display import print_text_result
from reporails_cli.interfaces.cli.helpers import console

logger = logging.getLogger(__name__)


def _resolve_capability_paths_one(
    capability: str,
    capability_name: str,
    effective_agent: str,
    project_root: Path,
    exclude_dirs: list[str] | tuple[str, ...] | None = None,
) -> tuple[set[Path], list[Any]]:
    """Resolve one (capability, name) spec to its file set + unresolved-skill list; a spec that
    names no file prints why and exits 2."""
    from reporails_cli.core.classify.capability_paths import TargetError, resolve_capability_spec

    try:
        return resolve_capability_spec(capability, capability_name, effective_agent, project_root, exclude_dirs)
    except TargetError as err:
        if err.reason == "undeclared":
            console.print(
                f"[red]Error:[/red] capability [bold]{capability}[/bold] is not declared "
                f"for agent [bold]{effective_agent}[/bold]. "
                f"Available: {', '.join(err.available) or '(none)'}"
            )
            raise typer.Exit(2) from err
        console.print(
            f"[red]Error:[/red] no {capability} named [bold]{capability_name}[/bold] "
            f"for agent [bold]{effective_agent}[/bold] under {project_root}."
        )
        if err.available:
            console.print(
                f"[dim]Found {len(err.available)} {capability}(s) — run `ails check @{capability}` to list.[/dim]"
            )
        raise typer.Exit(2) from err


def _resolve_capability_paths(
    specs: list[tuple[str, str]],
    effective_agent: str,
    project_root: Path,
    exclude_dirs: list[str] | tuple[str, ...] | None = None,
) -> tuple[set[Path], list[Any]]:
    """Union of every (capability, name) spec resolved against the agent's vocabulary."""
    paths: set[Path] = set()
    unresolved: list[Any] = []
    for capability, capability_name in specs:
        one_paths, one_unresolved = _resolve_capability_paths_one(
            capability, capability_name, effective_agent, project_root, exclude_dirs
        )
        paths |= one_paths
        unresolved.extend(one_unresolved)
    return paths, unresolved


def _resolved_within_target(f: Path, target: Path) -> bool:
    """True when the file's real (symlink-resolved) location is within the heal target.

    Heal writes through to the real file, so an in-tree symlink whose resolved path
    escapes the target must not be written — never mutate a file outside the named scope.
    """
    fr = safe_resolve(f)
    tr = safe_resolve(target)
    return fr == tr or fr.is_relative_to(tr)


def _is_project_root(directory: Path) -> bool:
    """True when `directory` is itself a project root, not a slice of the enclosing one.

    Two markers, both read off disk at `directory`'s own top level:

    * an `.ails/` directory — the validator's own project marker; or
    * a supported agent's MAIN instruction file together with a config directory of
      that same agent (`CLAUDE.md` + `.claude/`, `.github/copilot-instructions.md` +
      `.github/`). Both halves are required: a monorepo package carrying its own
      agent surfaces is a root, a directory holding only a stray main file is not.

    An agent's own config directory (`.claude/`, `.codex/`, …) is never a root, whatever
    it contains — a `CLAUDE.md` that someone dropped inside `.claude/` is a misplaced
    file in THIS project, not the root of another one.
    """
    if directory.name in agent_dir_names():
        return False
    if (directory / ".ails").is_dir():
        return True
    return any(
        any(_has_file(directory, main) for main in mains) and any((directory / d).is_dir() for d in dirs)
        for mains, dirs in root_markers()
    )


def _has_file(directory: Path, rel: str) -> bool:
    """Whether `rel` is a file under `directory`, its name matched whatever its case (`claude.md`), as
    discovery finds instruction files."""
    path = directory / rel
    if path.is_file():
        return True
    try:
        entries = list(path.parent.iterdir()) if path.parent.is_dir() else []
    except OSError:
        return False
    return any(e.name.lower() == path.name.lower() and e.is_file() for e in entries)


def _has_any_main_file(directory: Path) -> bool:
    """True when `directory` holds any supported agent's MAIN instruction file at its own
    top level, its config directory or not.

    Looser than `_is_project_root`'s paired check — used only to tell whether the
    ENCLOSING root has agent surfaces of its own, never to decide the target's own
    root-ness (that stays paired, so a stray main file inside a real slice does not
    turn the slice into a root).
    """
    return any(_has_file(directory, main) for mains, _ in root_markers() for main in mains)


def _has_project_markers(directory: Path) -> bool:
    """True when `directory` already carries a project marker of its own at its own top
    level: an `.ails/` directory, any supported agent's config directory (`.claude/`,
    `.codex/`, …, per `agent_dir_names`), or any supported agent's MAIN instruction file.

    The same markers `_is_project_root` inspects, but without requiring the main-file +
    config-dir pairing — used only to tell whether the ENCLOSING root already anchors a
    project of its own, so the bare-main-file branch below never fires under it. Without
    the config-dir and `.ails/` halves, a project that carries rules or skills but no main
    file at its own root (a `.claude/rules/`-only project) read as agent-less, so a bare
    main file dropped inside its `.claude/` still won anchoring and split the run off from
    the project's own rules and skills.
    """
    if (directory / ".ails").is_dir():
        return True
    if any((directory / d).is_dir() for d in agent_dir_names()):
        return True
    return _has_any_main_file(directory)


def _enclosing_project(path: Path, project_root: Path) -> Path:
    """The project a FILE or FOLDER target sits in: `project_root` (the cwd's project) when the
    target lies inside it, so a nested target stays scoped to the whole project it belongs to,
    never re-rooted onto its own package/skill folder. A target OUTSIDE `project_root` walks up
    from itself (`resolve_project_root_for_file`, the same function MCP's `validate` tool uses)
    to find its own real project, since `project_root` there is not that project at all. When
    `project_root` is no project (a parent holding several checkouts, a temp folder, `/`), a
    real project root found above the target scopes the run, never the unrelated folder around it."""
    if not path.is_relative_to(project_root):
        return resolve_project_root_for_file(path)
    if _has_project_markers(project_root):
        return project_root
    own = resolve_project_root_for_file(path)
    if own != project_root and own.is_relative_to(project_root) and _is_own_project(own):
        return own
    return project_root


def _file_target_root(single_file: Path, project_root: Path) -> Path:
    """Root for a lone FILE target: its enclosing project (`_enclosing_project`). A file in the
    user's own agent folder (`~/.claude`) roots on that folder alone, wherever the command runs from."""
    user_dir = user_level_agent_dir(single_file)
    if user_dir is not None:
        return user_dir
    return _enclosing_project(single_file, project_root)


def _is_own_project(directory: Path) -> bool:
    """True when `directory` is a project root of its own: a `.git` folder, or the markers `_is_project_root` reads."""
    return (directory / ".git").exists() or _is_project_root(directory)


def _agent_config_holder(directory: Path, project_root: Path) -> Path | None:
    """The project that holds `directory` when it is an agent's own configuration folder (`.claude/`,
    `.codex/`, …) or a folder inside one (`.claude/rules/`), named from outside that project, from a
    folder that is no project, or run from inside it (the current folder is `project_root`), else None.

    Such a folder is never a project of its own; its rules and skills belong to the project around it.
    """
    if user_level_agent_dir(directory):
        return None
    if directory != project_root and directory.is_relative_to(project_root) and _has_project_markers(project_root):
        return None
    holder = resolve_project_root_for_file(directory)
    if holder == directory or not directory.is_relative_to(holder):
        return None
    return holder if directory.relative_to(holder).parts[0] in agent_dir_names() else None


def _scan_root(single_path: Path | None, single_file: Path | None, project_root: Path) -> tuple[Path | None, Path]:
    """Resolve a lone path target to `(subtree, scan_root)`.

    A lone FILE target keeps today's root (`project_root`, the project resolved from the
    invoking terminal's cwd) whenever the file lies INSIDE that root — a nested child file
    (`packages/api/CLAUDE.md`, a skill's `SKILL.md`) stays scoped to the whole project it
    belongs to, exactly as before; walking up FROM the file here would anchor it at
    whatever marker-bearing directory happens to sit above it (its own package, its own
    skill folder), silently re-rooting and re-scoping a file that was never meant to be
    its own project. Only a file OUTSIDE `project_root` — given from elsewhere entirely
    (`cd /tmp && ails check /abs/proj/CLAUDE.md`), or above the cwd within its own project
    (`cd proj/.claude && ails check ../CLAUDE.md`) — walks up from the file itself
    (`resolve_project_root_for_file`, the same function MCP's `validate` tool uses) to
    find that file's real project, since `project_root` there is not that project at all.

    A lone DIRECTORY target resolves by one question — is it a project root of its own? —
    asked against the project it sits in (`_enclosing_project`, the walk a file target
    takes), so a folder named from a terminal outside its project reads the same as when named
    from within.

    * A root (another checkout, or a monorepo package carrying its own `.ails/` or
      `CLAUDE.md` + `.claude/`) is anchored as its own scan root and keeps its own path
      keys and level. So is a folder that is its own project (the current folder, or the
      walk up from it ends at the folder itself).
    * A directory holding any project marker (a bare main instruction file, an agent
      config directory without a main file, an `.ails/`) is ALSO anchored as its own root
      when the enclosing project carries no project marker of its own (no `.ails/`,
      no agent config directory, no main file —
      `_has_project_markers`, mirroring `_is_project_root`'s own marker check) —
      anchoring at that enclosing root would detect no agent at all and silently drop
      the target, the same way a lone `CLAUDE.md` repo checked from its parent must
      still be found. An enclosing project that already carries a marker of its own (an
      `.ails`- or `.claude/rules/`-anchored project, say) keeps the folder as
      a slice instead, so its own rules and skills are not split off from it.
    * Anything else inside the enclosing project is a SLICE of it. Discovery finds an
      agent's surfaces (`.claude/rules/`, `.claude/skills/`) only relative to the
      project root, so the scan stays anchored there and is narrowed to the subtree —
      `subtree` names it for the caller.

    Deciding on the root marker rather than on "did anchoring here find anything"
    matters for a slice that discovery can partly resolve on its own: anchoring at
    `.claude/` finds a stray `.claude/CLAUDE.md` and nothing else, so an
    empty-result fallback never fires and the rules and skills underneath are silently
    dropped from the run.
    """
    if single_file is None:
        # The folder in scope is the target, or the current folder when none is named.
        scoped = single_path or project_root
        holder = _agent_config_holder(scoped, project_root)
        if holder is not None:
            return scoped, holder
    if single_path is None:
        return None, project_root
    if single_file is not None:
        return None, _file_target_root(single_file, project_root)
    enclosing = _enclosing_project(single_path, project_root)
    if single_path == enclosing or not single_path.is_relative_to(enclosing):
        return None, single_path
    if _is_project_root(single_path) or (not _has_project_markers(enclosing) and _has_project_markers(single_path)):
        return None, single_path
    return single_path, enclosing


def _existing_target_root(token: str, project_root: Path) -> Path | None:
    """The scan root of a target token that names an existing file or folder, else None.

    A capability form (`@skills`, `skills:backlog`) and a word that names nothing on disk
    return None: those are read against the current folder's project.
    """
    from reporails_cli.core.classify.capability_paths import looks_like_windows_path

    raw = token[len("file:") :] if token.startswith("file:") else token
    if raw.startswith("@") or (":" in raw and not looks_like_windows_path(raw)):
        return None
    try:
        path = safe_resolve(Path(raw))
        if not path.exists():
            return None
        return _scan_root(path, path if path.is_file() else None, project_root)[1]
    except OSError:
        return None


def _token_agent(token: str, agent: str, project_root: Path, sniffed: dict[Path, str]) -> str:
    """The agent whose vocabulary reads `token`: sniffed under the project of an existing path
    target, under the current folder's project for anything else (`sniffed` caches per root)."""
    from reporails_cli.core.classify.capability_paths import sniff_agent

    root = _existing_target_root(token, project_root) or project_root
    if root not in sniffed:
        sniffed[root] = sniff_agent(agent, root)
    return sniffed[root]


def _narrow_to_path_targets(instruction_files: list[Path], path_targets: set[Path]) -> list[Path]:
    """Keep only instruction files that are equal to or beneath one of `path_targets`."""
    return [f for f in instruction_files if any(_file_under_target(f, tgt) for tgt in path_targets)]


def _file_under_target(f: Path, tgt: Path) -> bool:
    """True when instruction file `f` is the target or sits beneath it.

    Tests the file's logical absolute path alongside its symlink-resolved path so a
    directory target keeps in-tree symlinked files (e.g. symlinked rules) instead
    of dropping them when resolution escapes the target. The single shared check used
    by both the single-directory narrowing and the multi-path `--target` narrowing.
    """
    import contextlib
    import os

    candidates = [Path(os.path.abspath(f))]
    # A symlink loop resolves nowhere; its logical path stands alone.
    with contextlib.suppress(OSError, RuntimeError):
        candidates.append(safe_resolve(f))
    if tgt.is_file():
        return any(p == tgt for p in candidates)
    if tgt.is_dir():
        return any(p == tgt or p.is_relative_to(tgt) for p in candidates)
    return False


def _relativize_paths(paths: set[Path], project_root: Path) -> set[str]:
    return {p.relative_to(project_root).as_posix() if p.is_relative_to(project_root) else p.as_posix() for p in paths}


# The formats `_dispatch_output` actually routes — the live registry, and the only
# values `ails check --format` accepts. Keep it beside the dispatcher it describes:
# a retired formatter (`compact`, `brief`) that stayed accepted fell through to the
# human scorecard at exit 0, so a CI job pinned to it silently stopped machine-parsing.
OUTPUT_FORMATS = ("text", "json", "github")


def _validate_output_format(output_format: str | None) -> None:
    """Reject an unknown `--format` with a usage error naming the formats that exist."""
    if output_format and output_format not in OUTPUT_FORMATS:
        console.print(f"[red]Error:[/red] Unknown format: {output_format}")
        console.print(f"Valid formats: {', '.join(OUTPUT_FORMATS)}")
        raise typer.Exit(2)


def _dispatch_output(
    output_format: str,
    display_result: Any,
    ruleset_map: Any,
    elapsed_ms: float,
    capability_paths: set[Path],
    project_root: Path,
    ascii_mode: bool,
    verbose: bool,
    funnel_error: Any,
    file_type_by_path: dict[str, str] | None = None,
) -> None:
    """Route formatted output to JSON / GitHub / text.

    Every format consumes `funnel_error` by attaching it onto the `CombinedResult` as
    `server_error` before formatting — a server rejection, timeout, or network failure
    otherwise reads identically to a designed-offline run (`offline: true` with no reason).
    Text also renders `funnel_error` directly via its CTA path (`_render_funnel_cta`).
    """
    from dataclasses import replace

    from reporails_cli.core.platform.dto.diagnostics import FunnelError
    from reporails_cli.formatters import json as json_formatter

    result_for_output = display_result
    if isinstance(funnel_error, FunnelError):
        result_for_output = replace(display_result, server_error=funnel_error)

    if output_format == "json":
        from reporails_cli.core.platform.observability.stage_timer import get_stage_timer

        data = json_formatter.format_combined_result(
            result_for_output,
            ruleset_map=ruleset_map,
            project_root=project_root,
            file_type_by_path=file_type_by_path,
        )
        data["elapsed_ms"] = round(elapsed_ms, 1)
        timer = get_stage_timer()
        if timer.enabled:
            data["timing"] = timer.as_dict()
        if capability_paths:
            data["capability_paths"] = sorted(_relativize_paths(capability_paths, project_root))
        print(json.dumps(data, indent=2))
        return
    if output_format == "github":
        from reporails_cli.formatters import github as github_formatter

        print(
            github_formatter.format_combined_annotations(
                result_for_output,
                ruleset_map=ruleset_map,
                project_root=project_root,
                file_type_by_path=file_type_by_path,
                elapsed_ms=elapsed_ms,
            )
        )
        return
    from reporails_cli.core.platform.adapters.notices_seen import due_notices

    # Only the notices due today are shown; JSON above carries them all.
    print_text_result(
        replace(result_for_output, notices=due_notices(result_for_output.notices)),
        elapsed_ms,
        ascii_mode,
        verbose,
        ruleset_map=ruleset_map,
        funnel_error=funnel_error,
        project_root=project_root,
        file_type_by_path=file_type_by_path,
    )


def _emit_stage_timing(stage_timer: Any, output_format: str) -> None:
    """Print the per-stage timing table (dev-only, gated by `AILS_STAGE_TIMING`).

    Only renders when the timer was enabled via the env var; the internal stage
    names never reach the default text / JSON output.
    """
    if output_format == "json" or not stage_timer.enabled or not stage_timer.records:
        return
    console.print("\n  [dim]── Stage timing (wall-clock) ──[/dim]")
    for line in stage_timer.render_lines():
        console.print(f"  [dim]{line}[/dim]")


def _run_heal_pass(
    target: Path,
    instruction_files: list[Path],
    ruleset_map: Any,
    effective_agent: str,
    dry_run: bool,
    output_format: str,
    notices: Any = (),
) -> None:
    """Apply mechanical fixes and collect section suggestions using the already-built map."""
    from reporails_cli.core.lint.suppression import suppressed_lines
    from reporails_cli.interfaces.cli.heal import (
        _apply_mechanical_fixes,
        _collect_section_suggestions,
        _output_heal_results,
    )

    show = sys.stdout.isatty() and output_format != "json"
    heal_start = time.perf_counter()
    # A line the author annotated with an `ails-disable-line` directive is reviewed —
    # heal must not mechanically rewrite it. Key the suppressed lines by resolved path
    # so they match the atom files regardless of path form.
    supp_raw = suppressed_lines([str(f) for f in instruction_files], target)
    suppressed = {safe_resolve(Path(k)): v for k, v in supp_raw.items()}
    # The mechanical pass writes only within the scoped `instruction_files` set — it
    # cannot rewrite a mapped file outside scope. Section suggestions never write.
    mech = _apply_mechanical_fixes(ruleset_map, target, dry_run, show, console, instruction_files, suppressed)
    suggested = _collect_section_suggestions(target, instruction_files, ruleset_map, effective_agent, show, console)
    heal_ms = round((time.perf_counter() - heal_start) * 1000, 1)
    _output_heal_results(mech, suggested, dry_run, heal_ms, output_format, console, notices)


# A key the server rejected, quoted back to the caller as `FunnelError.error`.
# `--strict` treats either as a hard failure regardless of local findings: a CI job
# passing a revoked or malformed key must not read as a clean run just because
# the tree it happened to check carries no findings of its own.


def _should_exit_strict(
    strict: bool,
    capability_paths: set[Path],
    project_root: Path,
    result: Any,
    funnel_error: Any = None,
) -> bool:
    if not strict:
        return False
    from reporails_cli.core.platform.dto.diagnostics import AUTH_REJECTED_ERRORS, FunnelError

    if isinstance(funnel_error, FunnelError) and funnel_error.error in AUTH_REJECTED_ERRORS:
        return True
    if capability_paths:
        # Key the scope set with the SAME normalization the display filter uses
        # (`normalize_finding_path`), not `_relativize_paths`. The two diverge for
        # user-scope paths (`~/.claude/...`), so a strict run on such a target could
        # exit 0 while the display showed errors for it.
        from reporails_cli.core.platform.runtime.merger import normalize_finding_path

        rel_keys = {normalize_finding_path(str(p), project_root) for p in capability_paths}
        return any(f.file in rel_keys for f in result.findings)
    return bool(result.findings)


def _quiet_mapper_logs() -> None:
    """Keep the mapper's info-level logs off stderr during a check."""
    import logging as _logging

    _logging.getLogger("reporails_cli.core.mapper").setLevel(_logging.ERROR)
