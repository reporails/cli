"""The files a session could load, and the turns each sat in context."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from reporails_cli.core.pipeline.expected_loads import expected_loads
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.contract.json_value import JsonObject, as_list, as_object, as_str
from reporails_cli.core.platform.dto.events import EventRecord, HarnessKind
from reporails_cli.core.platform.dto.xray import (
    ARTIFACT_KIND_OF_FILE_TYPE,
    INVOCABLE_ARTIFACT_KINDS,
    RUNNABLE_ARTIFACT_KINDS,
    SCOPE_PRECEDENCE,
    ArtifactFile,
    ArtifactKind,
    ArtifactScope,
    FindingTally,
    XrayArtifact,
    XrayCompaction,
    XrayLoad,
    XraySubagent,
    XrayTurn,
    is_artifact_scope,
)
from reporails_cli.core.xray.derive import count_for, file_tokens_est, real_path

# What Claude Code re-attaches after a compaction: the first tokens of each skill's latest run, and the most all
# re-attached skills share (https://code.claude.com/docs/en/skills, "Auto-compaction carries invoked skills forward").
SKILL_REATTACH_TOKENS = 5_000
SKILL_REATTACH_BUDGET = 25_000

# The most characters of a file the page may ask for.
PEEK_LIMIT = 200_000


def _scope_of(item: JsonObject) -> ArtifactScope:
    precedence = as_str(item.get("precedence"))
    if not is_artifact_scope(precedence):
        raise ValueError(f"{as_str(item.get('path'))}: no artifact scope for precedence {precedence!r}")
    return precedence


def _loaded_file(item: JsonObject, kind: ArtifactKind) -> ArtifactFile:
    linked = item.get("linked")
    return ArtifactFile(
        as_str(item.get("path")),
        kind,
        _scope_of(item),
        None,
        as_str(item.get("label")),
        as_str(item.get("memory_type")) or None,
        linked if isinstance(linked, bool) else None,
    )


def _invocable_file(item: JsonObject) -> ArtifactFile:
    return ArtifactFile(
        as_str(item.get("path")),
        ARTIFACT_KIND_OF_FILE_TYPE[as_str(item.get("file_type"))],
        _scope_of(item),
        as_str(item.get("plugin")) or None,
        as_str(item.get("label")),
        None,
        None,
    )


def artifact_files(root: Path, plugins: Sequence[tuple[str, Path]]) -> tuple[ArtifactFile, ...]:
    """Every file the session could load, as `expected_loads` lists them: the instruction, rule and memory files
    Claude Code loads for the folder, and the skills, agents, commands and hook configs a session can invoke
    from every scope and each of `plugins`; a skill's supporting file is no artifact of its own."""
    loads = expected_loads(root, plugins)
    files = [_invocable_file(as_object(item)) for item in as_list(loads.get("invocable"))]
    for entry in as_list(loads.get("files")):
        loaded = as_object(entry)
        kind = ARTIFACT_KIND_OF_FILE_TYPE.get(as_str(loaded.get("file_type")), "instructions")
        if kind not in INVOCABLE_ARTIFACT_KINDS:
            files.append(_loaded_file(loaded, kind))
    first: dict[str, ArtifactFile] = {}
    for item in files:
        first.setdefault(item.path, item)
    return tuple(first.values())


def winners(files: Sequence[ArtifactFile], kinds: frozenset[ArtifactKind]) -> dict[str, ArtifactFile]:
    """The file each label stands for among the listed files of `kinds`: the one of the scope that wins, the first
    listed when two share a scope."""

    def rank(item: ArtifactFile) -> int:
        order = SCOPE_PRECEDENCE[item.kind]
        return order.index(item.scope) if item.scope in order else len(order)

    found: dict[str, ArtifactFile] = {}
    for item in files:
        held = found.get(item.label)
        if item.kind in kinds and (held is None or rank(item) < rank(held)):
            found[item.label] = item
    return found


def runnable_paths(files: Sequence[ArtifactFile]) -> dict[str, str]:
    """The absolute path of the skill or command file each label stands for."""
    return {label: item.path for label, item in winners(files, RUNNABLE_ARTIFACT_KINDS).items()}


@dataclass(frozen=True)
class _Step:
    """One thing that put a file in context at a time: a load, a run, or (no path) a compaction."""

    t: float
    path: str | None
    run_tokens: int | None = None


def _ordered(
    start: Sequence[XrayLoad], turns: Sequence[XrayTurn], compactions: Sequence[XrayCompaction]
) -> list[tuple[int, list[_Step]]]:
    """Per turn number (0 = the session start), its loads, the runs of listed skill and command files that ran in
    the main session and every compaction that ran in it, in time order."""
    groups: list[tuple[int, list[_Step]]] = [(0, [_Step(load.t or 0.0, load.path) for load in start])]
    for turn in turns:
        steps = [_Step(load.t or 0.0, load.path) for load in turn.loads]
        steps.extend(
            _Step(run.t, run.path, run.tokens_est or 0)
            for run in turn.skill_runs
            if run.path is not None and not run.forked
        )
        steps.extend(_Step(compaction.t, None) for compaction in compactions if compaction.turn == turn.n)
        groups.append((turn.n, sorted(steps, key=lambda step: step.t)))
    return groups


def _reattached(ran: dict[str, int]) -> set[str]:
    """The skills a compaction brings back: the latest run of each, most recent first, until the combined budget is
    spent; `ran` maps a path to its re-attached size in tokens, oldest run first."""
    kept: set[str] = set()
    spent = 0
    for path, tokens in reversed(ran.items()):
        if spent + tokens > SKILL_REATTACH_BUDGET:
            break
        kept.add(path)
        spent += tokens
    return kept


def in_context_turns(
    start: Sequence[XrayLoad], turns: Sequence[XrayTurn], compactions: Sequence[XrayCompaction], root: Path
) -> dict[str, list[int]]:
    """For each resolved file path, the turn numbers it sat in context (0 = the session start).

    A loaded file stays in context until a compaction; after one it counts again only when a load names it again.
    A skill or command that ran also stays until a compaction, which brings back the latest run of each within
    the re-attach budget."""
    present: set[str] = set()
    ran: dict[str, int] = {}
    seen: dict[str, list[int]] = {}
    for number, steps in _ordered(start, turns, compactions):
        in_turn = set(present)
        for step in steps:
            if step.path is None:
                present = _reattached(ran)
                continue
            resolved = real_path(step.path, root)
            present.add(resolved)
            in_turn.add(resolved)
            if step.run_tokens is not None:
                ran.pop(resolved, None)
                ran[resolved] = min(step.run_tokens, SKILL_REATTACH_TOKENS)
        for resolved in in_turn:
            seen.setdefault(resolved, []).append(number)
    return seen


def run_paths(turns: Sequence[XrayTurn], root: Path) -> set[str]:
    """The resolved paths of the listed skill and command files that ran in the main session."""
    return {
        real_path(run.path, root)
        for turn in turns
        for run in turn.skill_runs
        if run.path is not None and not run.forked
    }


def agent_run_turns(
    subagents: Sequence[XraySubagent], files: Sequence[ArtifactFile], root: Path
) -> dict[str, list[int]]:
    """For each resolved path, the turns a subagent put its file in context in: an agent file in the turn a subagent
    of its type ran, a skill or command file in the turn a subagent ran it. A built-in type matches no file; a run
    that itself ran in a subagent counts for neither."""
    agents = _agent_paths(files, root)
    found: dict[str, list[int]] = {}
    for run in subagents:
        if run.turn is None:
            continue
        for path in _ran_paths(run, agents, root):
            found.setdefault(path, []).append(run.turn)
    return {path: sorted(set(turns)) for path, turns in found.items()}


def _agent_paths(files: Sequence[ArtifactFile], root: Path) -> dict[str, str]:
    """The resolved path of the agent file each agent type stands for."""
    return {label: real_path(item.path, root) for label, item in winners(files, frozenset({"agent"})).items()}


def _ran_paths(run: XraySubagent, agents: Mapping[str, str], root: Path) -> list[str]:
    """The resolved paths a subagent put in context by what it ran as: its agent file and the skill or command
    files it ran non-forked."""
    paths = [agents[run.type]] if run.type is not None and run.type in agents else []
    return paths + [real_path(item.path, root) for item in run.skill_runs if item.path is not None and not item.forked]


def context_counts(
    main: Mapping[str, list[int]], subagents: Sequence[XraySubagent], files: Sequence[ArtifactFile], root: Path
) -> dict[str, int]:
    """For each resolved path, the contexts it entered: the main session's (`main` holds the turns it sat in
    there) and each subagent's, by its loads and by what it ran as."""
    agents = _agent_paths(files, root)
    counts = dict.fromkeys(main, 1)
    for run in subagents:
        entered = {real_path(load.path, root) for load in run.loads} | set(_ran_paths(run, agents, root))
        for path in entered:
            counts[path] = counts.get(path, 0) + 1
    return counts


def _listed_names(records: Sequence[EventRecord], kind: HarnessKind) -> set[str] | None:
    """The names the main session's listing rows of `kind` carry: a skill listing's `names`, an agent listing's
    added names; None when no such row carries any."""
    found: set[str] | None = None
    for record in records:
        entry = record.harness
        if record.subagent_id is not None or entry is None or entry.kind != kind:
            continue
        names = entry.names if kind == "skill_list" else tuple(name for name, _ in entry.added)
        if names is not None:
            found = (found or set()) | set(names)
    return found


def advertised_files(files: Sequence[ArtifactFile], records: Sequence[EventRecord]) -> dict[str, bool | None]:
    """For each listed skill, command and agent file (by path), whether a listing row names its label and the file
    is the one its label stands for; None when no listing row of its kind names anything."""
    skills = _listed_names(records, "skill_list")
    agents = _listed_names(records, "agent_list")
    runnable = winners(files, RUNNABLE_ARTIFACT_KINDS)
    agent_files = winners(files, frozenset({"agent"}))
    found: dict[str, bool | None] = {}
    for item in files:
        if item.kind in RUNNABLE_ARTIFACT_KINDS:
            found[item.path] = None if skills is None else item.label in skills and runnable[item.label] == item
        elif item.kind == "agent":
            found[item.path] = None if agents is None else item.label in agents and agent_files[item.label] == item
    return found


def merged_turns(first: Mapping[str, list[int]], second: Mapping[str, list[int]]) -> dict[str, list[int]]:
    """The turns of two per-path maps, each path's turns together in order."""
    return {path: sorted({*first.get(path, []), *second.get(path, [])}) for path in {*first, *second}}


def is_actionable(item: ArtifactFile, root: Path) -> bool:
    """True for a file of the project that exists and is not a hook config: the files the page may check or fix."""
    if item.kind == "hook":
        return False
    return Path(item.path).is_relative_to(root) and Path(real_path(item.path, root)).is_file()


def build_artifacts(
    files: Sequence[ArtifactFile],
    loaded: set[str],
    in_context: Mapping[str, list[int]],
    findings: Mapping[str, FindingTally],
    root: Path,
    advertised: Mapping[str, bool | None],
    contexts: Mapping[str, int],
) -> tuple[XrayArtifact, ...]:
    """The artifact list: `loaded`, `in_context` and `contexts` are keyed by resolved path, `advertised` by the
    file's path."""
    out: list[XrayArtifact] = []
    for item in files:
        resolved = real_path(item.path, root)
        tokens_est = file_tokens_est(resolved)
        entered = contexts.get(resolved, 0)
        out.append(
            XrayArtifact(
                path=relative_wire_path(item.path, root),
                kind=item.kind,
                scope=item.scope,
                plugin=item.plugin,
                label=item.label,
                memory_type=item.memory_type,
                linked=item.linked,
                loaded=resolved in loaded,
                turns=tuple(in_context.get(resolved, ())),
                findings=count_for(findings, item.path, root),
                actionable=is_actionable(item, root),
                tokens_est=tokens_est,
                advertised=advertised.get(item.path),
                contexts=entered,
                session_tokens_est=None if tokens_est is None else tokens_est * entered,
            )
        )
    return tuple(out)


def peek_text(item: ArtifactFile, root: Path) -> tuple[str, bool] | None:
    """The text of a listed file, cut at `PEEK_LIMIT` characters, and whether it was cut; None when the path is
    not a readable file."""
    path = Path(real_path(item.path, root))
    try:
        if not path.is_file():
            return None
        with path.open(encoding="utf-8", errors="replace") as handle:
            text = handle.read(PEEK_LIMIT + 1)
    except OSError:
        return None
    return text[:PEEK_LIMIT], len(text) > PEEK_LIMIT
