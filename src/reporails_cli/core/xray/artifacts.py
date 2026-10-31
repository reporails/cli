"""The files a session could load, and the turns each sat in context."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from reporails_cli.core.discovery.agent_config import extract_patterns, load_config_file_types
from reporails_cli.core.discovery.agent_discovery import MEMORY_SURFACES, discover_ungated
from reporails_cli.core.discovery.exclusions import load_run_exclusions
from reporails_cli.core.discovery.features import detect_features_filesystem
from reporails_cli.core.discovery.plugin_roots import entry_pattern
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.pipeline.expected_loads import AGENT, expected_loads
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.contract.json_value import as_list, as_object, as_str
from reporails_cli.core.platform.dto.xray import ArtifactKind, XrayArtifact, XrayLoad, XrayTurn
from reporails_cli.core.xray.derive import count_for, real_path

# The most characters of a file the page may ask for.
PEEK_LIMIT = 200_000


@dataclass(frozen=True)
class ArtifactFile:
    """One file the session could load: its absolute path and what kind of file it is."""

    path: str
    kind: ArtifactKind


def _instruction_files(root: Path) -> list[ArtifactFile]:
    files = as_list(expected_loads(root).get("files"))
    found: list[ArtifactFile] = []
    for entry in files:
        item = as_object(entry)
        path = as_str(item.get("path"))
        if path:
            kind: ArtifactKind = "memory" if as_str(item.get("file_type")) in MEMORY_SURFACES else "instructions"
            found.append(ArtifactFile(path, kind))
    return found


def _surface_files(root: Path, surface: str) -> list[Path]:
    return discover_ungated(
        root, AGENT, (surface,), load_run_exclusions(root, None, None), project_config=get_project_config(root)
    )


def _hook_files(root: Path) -> list[Path]:
    labels = {entry.file for entry in detect_features_filesystem(root).hooks if entry.agent == AGENT}
    return [Path(label).expanduser() if label.startswith("~") else root / label for label in sorted(labels)]


def artifact_files(root: Path) -> tuple[ArtifactFile, ...]:
    """Every file the session could load: the instruction and memory files Claude Code loads for the
    folder, the project's skills and agents, and the files that configure hooks."""
    entries = extract_patterns(as_object(as_object(load_config_file_types(AGENT)).get("skills")), "entry_patterns")
    files = [
        ArtifactFile(str(path), "skill")
        for path in _surface_files(root, "skills")
        if entry_pattern(path, root, entries) is not None
    ]
    files.extend(ArtifactFile(str(path), "agent") for path in _surface_files(root, "agents"))
    files.extend(ArtifactFile(str(path), "hook") for path in _hook_files(root))
    files.extend(_instruction_files(root))
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
    path = safe_resolve(root / Path(item.path).expanduser())
    return Path(item.path).is_relative_to(root) and path.is_file()


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
                loaded=resolved in loaded,
                turns=tuple(in_context.get(resolved, ())),
                findings=count_for(findings, item.path, root),
                actionable=is_actionable(item, root),
            )
        )
    return tuple(out)


def peek_text(item: ArtifactFile, root: Path) -> tuple[str, bool] | None:
    """The text of a listed file, cut at `PEEK_LIMIT` characters, and whether it was cut; None when the path is
    not a readable file."""
    path = safe_resolve(root / Path(item.path).expanduser())
    try:
        if not path.is_file():
            return None
        with path.open(encoding="utf-8", errors="replace") as handle:
            text = handle.read(PEEK_LIMIT + 1)
    except OSError:
        return None
    return text[:PEEK_LIMIT], len(text) > PEEK_LIMIT
