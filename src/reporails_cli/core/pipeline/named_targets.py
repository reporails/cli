"""The targets a run names: how each was read, which were checked, and why each other one was not.

Each named target ends checked, or listed with one reason (`NotEvaluatedReason`). A bare word that is
both a folder and a capability gets a notice saying which meaning was used.
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
from reporails_cli.core.discovery.project_root import outermost_agent_dir
from reporails_cli.core.discovery.walk import file_under_target, is_markdown_file, safe_resolve, walk_files
from reporails_cli.core.pipeline.check_one import resolve_scan_target
from reporails_cli.core.pipeline.mapping import is_listed_file
from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.dto.classify import UnresolvedSkill
from reporails_cli.core.platform.dto.diagnostics import Notice
from reporails_cli.core.platform.dto.discovery import RunExclusions
from reporails_cli.core.platform.dto.targets import (
    MissingTarget,
    NotEvaluatedReason,
    TargetReading,
    TargetReport,
    UnevaluatedTarget,
)


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


class _TargetReader:
    """The state of one `read_targets` call: what the tokens read so far, and the agent each project root
    sniffs as."""

    def __init__(self, run: RunContext, agent: str, project_root: Path, base: Path | None) -> None:
        self.run = run
        self.agent = agent
        self.project_root = project_root
        self.base = base
        self.sniffed: dict[Path, str] = {}
        self.specs: list[tuple[str, str]] = []
        self.words: list[str] = []
        self.paths: set[Path] = set()
        self.missing: list[MissingTarget] = []
        self.unevaluated: list[UnevaluatedTarget] = []
        self.notices: list[Notice] = []

    def read(self, token: str) -> None:
        """Read `token` as a capability, a capability the agent lacks, or a path."""
        root = _existing_target_root(token, self.project_root, self.base) or self.project_root
        if root not in self.sniffed:
            self.sniffed[root] = sniff_agent(self.run, self.agent, root)
        token_agent = self.sniffed[root]
        kind, payload = classify_target_token(self.run, token, token_agent, self.project_root, self.base)
        config = self.run.project_config(self.project_root)
        if kind == "capability" and isinstance(payload, tuple):
            if token_agent and canonicalize_capability(payload[0], token_agent, config) is None:
                self.unevaluated.append(UnevaluatedTarget(token, "unknown_capability"))
                return
            self.specs.append(payload)
            self.words.append(token)
            if folder_shadowed_by_capability(token, "capability", self.base):
                self.notices.append(target_clash_notice(token, token_agent))
        elif isinstance(payload, Path):
            if payload.exists():
                self.paths.add(payload)
                return
            hint = bool(token_agent) and canonicalize_capability(token, token_agent, config) is not None
            self.missing.append(MissingTarget(token, payload, hint))

    def reading(self) -> TargetReading:
        """What the tokens read."""
        return TargetReading(
            tuple(self.specs),
            tuple(self.words),
            frozenset(self.paths),
            tuple(self.missing),
            tuple(self.unevaluated),
            tuple(self.notices),
        )


def read_targets(
    run: RunContext, tokens: Iterable[str], agent: str, project_root: Path, base: Path | None = None
) -> TargetReading:
    """Read each target token as a capability the agent has, a capability it lacks (listed as
    `unknown_capability`), or a path. A relative path is read against `base` (the working folder when
    None). The agent whose vocabulary reads a token is sniffed under the project of an existing path
    target, under `project_root` for anything else."""
    reader = _TargetReader(run, agent, project_root, base)
    for token in tokens:
        reader.read(token)
    return reader.reading()


def markdown_under_folders(folders: Iterable[Path], exclusions: RunExclusions) -> set[Path]:
    """The markdown files kept under the named `folders`, each checked whether or not an agent loads it."""
    return {
        f
        for folder in folders
        for f in walk_files(folder, exclusions, is_markdown_file)
        if not leaves_out(exclusions, f)
    }


def _file_reason(run: RunContext, path: Path, project_root: Path) -> NotEvaluatedReason:
    """Why a named non-markdown file no agent loads here was not checked: `other_project` when it sits in an
    agent folder of a project outside `project_root` that reads it as an agent's file, else `not_markdown`."""
    agent_dir = None if path.is_relative_to(project_root) else outermost_agent_dir(path)
    listed = agent_dir is not None and is_listed_file(run, path, agent_dir.parent)
    return "other_project" if listed else "not_markdown"


def unchecked_paths(
    run: RunContext,
    path_targets: Iterable[Path],
    checked: Iterable[Path],
    *,
    exclusions: RunExclusions,
    project_root: Path,
    scan_target: Path,
) -> list[UnevaluatedTarget]:
    """Each named folder none of the `checked` files sits under, and each non-markdown file no agent loads
    here: `other_project` when it is an agent's file of a project outside `project_root`.

    `project_root` and `scan_target` are the projects the run checks, so naming either lists nothing.
    """
    files = list(checked)
    out: list[UnevaluatedTarget] = []
    for path in sorted(set(path_targets) - {project_root, scan_target}):
        if path.is_dir():
            if any(file_under_target(f, path) for f in files):
                continue
            reason = markdown_folder_reason(exclusions, path)
            if reason is not None:
                out.append(UnevaluatedTarget(shown_path(path, project_root), reason))
        elif path.is_file() and not is_markdown_file(path) and not is_listed_file(run, path, scan_target):
            out.append(UnevaluatedTarget(shown_path(path, project_root), _file_reason(run, path, project_root)))
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
        *unchecked_paths(
            run,
            reading.path_targets,
            checked,
            exclusions=exclusions,
            project_root=project_root,
            scan_target=project_root,
        ),
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
