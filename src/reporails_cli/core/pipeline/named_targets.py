"""The targets a run names: how each was read, which were checked, and why each other one was not.

`ails check` and the server's `validate` both read their targets here, so the same targets get the
same answer: checked, or listed with one reason (`NotEvaluatedReason`), and a bare word that is both
a folder and a capability gets a notice saying which meaning was used.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from reporails_cli.core.classify.capability_paths import (
    TargetError,
    canonicalize_capability,
    classify_target_token,
    folder_shadowed_by_capability,
    looks_like_windows_path,
    sniff_agent,
)
from reporails_cli.core.classify.focus_expansion import resolve_capability_spec
from reporails_cli.core.discovery.exclusions import leaves_out, markdown_folder_reason
from reporails_cli.core.discovery.walk import file_under_target, is_markdown_file, safe_resolve, walk_files
from reporails_cli.core.pipeline.check_one import resolve_scan_target
from reporails_cli.core.pipeline.mapping import is_listed_file
from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.dto.classify import UnresolvedSkill
from reporails_cli.core.platform.dto.diagnostics import Notice
from reporails_cli.core.platform.dto.discovery import RunExclusions
from reporails_cli.core.platform.dto.targets import MissingTarget, TargetReading, TargetReport, UnevaluatedTarget


def target_clash_notice(token: str, agent: str) -> Notice:
    """The notice that a bare word naming both a capability of `agent` and a folder was read as the capability."""
    return Notice(
        id="target_clash",
        level="info",
        text=(
            f"`{token}` is both a capability of {agent} and a folder here; it was read as the capability. "
            f"Use `file:{token}` to check the folder."
        ),
    )


def shown_path(path: Path, project_root: Path) -> str:
    """`path` relative to the project when it sits inside, else as given."""
    return path.relative_to(project_root).as_posix() if path.is_relative_to(project_root) else str(path)


def _existing_target_root(token: str, project_root: Path, base: Path | None) -> Path | None:
    """The scan root of a target token that names an existing file or folder, else None.

    A capability form (`@skills`, `skills:backlog`) and a word that names nothing on disk
    return None: those are read against the project the run was started in.
    """
    raw = token[len("file:") :] if token.startswith("file:") else token
    if raw.startswith("@") or (":" in raw and not looks_like_windows_path(raw)):
        return None
    try:
        spelled = Path(raw)
        path = safe_resolve(spelled if base is None or spelled.is_absolute() else base / spelled)
        if not path.exists():
            return None
        return resolve_scan_target(path, project_root)[0]
    except OSError:
        return None


def read_targets(
    run: RunContext, tokens: Iterable[str], agent: str, project_root: Path, base: Path | None = None
) -> TargetReading:
    """Read each target token as a capability the agent has, a capability it lacks (listed as
    `unknown_capability`), or a path. A relative path is read against `base` (the working folder when
    None). The agent whose vocabulary reads a token is sniffed under the project of an existing path
    target, under `project_root` for anything else."""
    config = run.project_config(project_root)
    sniffed: dict[Path, str] = {}
    specs: list[tuple[str, str]] = []
    words: list[str] = []
    paths: set[Path] = set()
    missing: list[MissingTarget] = []
    unevaluated: list[UnevaluatedTarget] = []
    notices: list[Notice] = []
    for token in tokens:
        root = _existing_target_root(token, project_root, base) or project_root
        if root not in sniffed:
            sniffed[root] = sniff_agent(run, agent, root)
        token_agent = sniffed[root]
        kind, payload = classify_target_token(run, token, token_agent, project_root, base)
        if kind == "capability" and isinstance(payload, tuple):
            if token_agent and canonicalize_capability(payload[0], token_agent, config) is None:
                unevaluated.append(UnevaluatedTarget(token, "unknown_capability"))
                continue
            specs.append(payload)
            words.append(token)
            if folder_shadowed_by_capability(token, "capability", base):
                notices.append(target_clash_notice(token, token_agent))
        elif isinstance(payload, Path):
            if payload.exists():
                paths.add(payload)
                continue
            hint = bool(token_agent) and canonicalize_capability(token, token_agent, config) is not None
            missing.append(MissingTarget(token, payload, hint))
    return TargetReading(
        tuple(specs), tuple(words), frozenset(paths), tuple(missing), tuple(unevaluated), tuple(notices)
    )


def markdown_under_folders(folders: Iterable[Path], exclusions: RunExclusions) -> set[Path]:
    """The markdown files kept under the named `folders`, each checked whether or not an agent loads it."""
    return {
        f
        for folder in folders
        for f in walk_files(folder, exclusions, is_markdown_file)
        if not leaves_out(exclusions, f)
    }


def unchecked_paths(
    run: RunContext,
    path_targets: Iterable[Path],
    checked: Iterable[Path],
    exclusions: RunExclusions,
    project_root: Path,
    scan_target: Path,
) -> list[UnevaluatedTarget]:
    """Each named folder none of the `checked` files sits under, and each non-markdown file no agent loads."""
    files = list(checked)
    out: list[UnevaluatedTarget] = []
    for path in sorted(set(path_targets) - {project_root}):
        if path.is_dir():
            if any(file_under_target(f, path) for f in files):
                continue
            reason = markdown_folder_reason(exclusions, path)
            if reason is not None:
                out.append(UnevaluatedTarget(shown_path(path, project_root), reason))
        elif path.is_file() and not is_markdown_file(path) and not is_listed_file(run, path, scan_target):
            out.append(UnevaluatedTarget(shown_path(path, project_root), "not_markdown"))
    return out


def unchecked_capability(word: str, paths: set[Path], unresolved: list[UnresolvedSkill]) -> UnevaluatedTarget | None:
    """The `no_files` entry for a capability `word` that resolved to no file."""
    return None if paths or unresolved else UnevaluatedTarget(word, "no_files")


def target_report(
    run: RunContext,
    reading: TargetReading,
    checked: Iterable[Path],
    *,
    exclusions: RunExclusions,
    effective_agent: str,
    project_root: Path,
) -> TargetReport:
    """How a finished run read its targets: those none of the `checked` files came from, each with its reason,
    and the notices on how a word was read."""
    unevaluated = [
        *reading.unevaluated,
        *unchecked_paths(run, reading.path_targets, checked, exclusions, project_root, project_root),
    ]
    for (capability, name), word in zip(reading.capability_specs, reading.capability_words, strict=True):
        try:
            paths, unresolved = resolve_capability_spec(
                run, capability, name, effective_agent, project_root=project_root, exclusions=exclusions
            )
        except TargetError:
            continue
        entry = unchecked_capability(word, paths, unresolved)
        if entry is not None:
            unevaluated.append(entry)
    return TargetReport(tuple(unevaluated), reading.notices)
