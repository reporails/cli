"""The files a session could load, and the turns each sat in context."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from reporails_cli.core.pipeline.expected_loads import expected_loads
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.contract.json_value import JsonObject, as_list, as_object, as_str
from reporails_cli.core.platform.dto.xray import (
    ARTIFACT_KIND_OF_FILE_TYPE,
    INVOCABLE_ARTIFACT_KINDS,
    ArtifactFile,
    ArtifactKind,
    ArtifactScope,
    XrayArtifact,
    XrayLoad,
    XrayTurn,
    is_artifact_scope,
)
from reporails_cli.core.xray.derive import count_for, file_tokens_est, real_path

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


def _ordered(start: Sequence[XrayLoad], turns: Sequence[XrayTurn]) -> list[tuple[int, list[tuple[float, str | None]]]]:
    """Per turn number (0 = the session start), its loads and compactions in time order; a compaction is
    `(t, None)`."""
    groups: list[tuple[int, list[tuple[float, str | None]]]] = [(0, [(load.t or 0.0, load.path) for load in start])]
    for turn in turns:
        steps: list[tuple[float, str | None]] = [(load.t or 0.0, load.path) for load in turn.loads]
        if turn.compaction is not None:
            steps.append((turn.compaction.t, None))
        groups.append((turn.n, sorted(steps, key=lambda step: step[0])))
    return groups


def in_context_turns(start: Sequence[XrayLoad], turns: Sequence[XrayTurn], root: Path) -> dict[str, list[int]]:
    """For each resolved file path, the turn numbers it sat in context (0 = the session start).

    A loaded file stays in context until a compaction; after one it counts again only when a load
    names it again."""
    present: set[str] = set()
    seen: dict[str, list[int]] = {}
    for number, steps in _ordered(start, turns):
        in_turn = set(present)
        for _, path in steps:
            if path is None:
                present.clear()
                continue
            resolved = real_path(path, root)
            present.add(resolved)
            in_turn.add(resolved)
        for resolved in in_turn:
            seen.setdefault(resolved, []).append(number)
    return seen


def is_actionable(item: ArtifactFile, root: Path) -> bool:
    """True for a file of the project that exists and is not a hook config: the files the page may check or fix."""
    if item.kind == "hook":
        return False
    return Path(item.path).is_relative_to(root) and Path(real_path(item.path, root)).is_file()


def build_artifacts(
    files: Sequence[ArtifactFile],
    loaded: set[str],
    in_context: Mapping[str, list[int]],
    findings: Mapping[str, int],
    root: Path,
) -> tuple[XrayArtifact, ...]:
    """The artifact list: `loaded` and `in_context` are keyed by resolved path."""
    out: list[XrayArtifact] = []
    for item in files:
        resolved = real_path(item.path, root)
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
                tokens_est=file_tokens_est(resolved),
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
