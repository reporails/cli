"""The files a session could load and the skill, command and agent files that ran."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from pathlib import Path

from reporails_cli.core.discovery.exclusions import exclusion_hits
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.pipeline.expected_loads import expected_loads
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.contract.json_value import JsonObject, as_list, as_object, as_str, pattern_list
from reporails_cli.core.platform.dto.events import EventRecord, HarnessKind
from reporails_cli.core.platform.dto.exclusion import FileLeftOut
from reporails_cli.core.platform.dto.xray_sources import (
    AGENT_ARTIFACT_KINDS,
    ARTIFACT_KIND_OF_FILE_TYPE,
    INVOCABLE_ARTIFACT_KINDS,
    RUNNABLE_ARTIFACT_KINDS,
    SCOPE_PRECEDENCE,
    ArtifactFile,
    ArtifactKind,
    ArtifactScope,
    FindingTally,
    XrayArtifact,
    XrayPeek,
    is_artifact_scope,
)
from reporails_cli.core.platform.utils.utils import frontmatter_block, read_frontmatter_file, strip_frontmatter
from reporails_cli.core.xray.derive import count_for, file_tokens_est, real_path

# The most characters of a file the page may ask for.
PEEK_LIMIT = 200_000

# The memory type an auto-memory file is loaded as.
AUTO_MEMORY_TYPE = "AutoMem"

# The frontmatter key a rule file lists the path patterns it applies to under.
RULE_SCOPE_KEY = "paths"


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


def unlisted_loads(records: Sequence[EventRecord], known: Collection[str], root: Path) -> list[ArtifactFile]:
    """The instruction and memory files the records show loaded that the listing leaves out, first load of each,
    with the kind the load's memory type gives; `known` holds the real paths of the files already listed."""
    seen = set(known)
    found: list[ArtifactFile] = []
    for record in records:
        if record.event != "instruction_load" or record.load is None:
            continue
        resolved = real_path(record.load.path, root)
        if resolved in seen:
            continue
        seen.add(resolved)
        kind: ArtifactKind = "memory" if record.load.memory_type == AUTO_MEMORY_TYPE else "instructions"
        found.append(
            ArtifactFile(
                record.load.path, kind, "project", None, Path(record.load.path).name, record.load.memory_type, None
            )
        )
    return found


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


def agent_file_tokens(files: Sequence[ArtifactFile], root: Path) -> dict[str, int]:
    """The size in tokens of the definition file each listed agent type stands for; a type whose file is unreadable
    is left out."""
    sizes = {
        label: file_tokens_est(real_path(item.path, root))
        for label, item in winners(files, AGENT_ARTIFACT_KINDS).items()
    }
    return {label: size for label, size in sizes.items() if size is not None}


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
    agent_files = winners(files, AGENT_ARTIFACT_KINDS)
    found: dict[str, bool | None] = {}
    for item in files:
        if item.kind in RUNNABLE_ARTIFACT_KINDS:
            found[item.path] = None if skills is None else item.label in skills and runnable[item.label] == item
        elif item.kind == "agent":
            found[item.path] = None if agents is None else item.label in agents and agent_files[item.label] == item
    return found


def is_actionable(item: ArtifactFile, root: Path) -> bool:
    """True for a file of the project that exists, whose real location is inside the project too, and that is not a
    hook config: the files the page may check or fix."""
    if item.kind == "hook":
        return False
    real = Path(real_path(item.path, root))
    return Path(item.path).is_relative_to(root) and real.is_file() and real.is_relative_to(safe_resolve(root))


def left_out_files(files: Sequence[ArtifactFile], root: Path) -> dict[str, FileLeftOut]:
    """For each file of the project that is no hook config (by its path), what keeps it out of a project-wide check
    or fix and, for a file whose real location is outside the project, where that location is, named as the page
    shows paths."""
    inside = [item for item in files if item.kind != "hook" and Path(item.path).is_relative_to(root)]
    hits = exclusion_hits(root, [Path(item.path) for item in inside])
    base = safe_resolve(root)
    found: dict[str, FileLeftOut] = {}
    for item in inside:
        path = Path(item.path)
        real = Path(real_path(item.path, root))
        outside = None
        if real.exists() and not real.is_relative_to(base):
            outside = relative_wire_path(str(real), root)
        found[item.path] = FileLeftOut(hits[path], outside)
    return found


def rule_scopes(item: ArtifactFile, root: Path) -> tuple[str, ...]:
    """The path patterns a rule file's frontmatter lists; none for any other kind of file, a file with no such
    key or one that cannot be read."""
    if item.kind != "rule":
        return ()
    read = read_frontmatter_file(Path(real_path(item.path, root)), lenient=True)
    if read is None or read.data is None:
        return ()
    return tuple(pattern_list(read.data.get(RULE_SCOPE_KEY, [])))


def build_artifacts(
    files: Sequence[ArtifactFile],
    findings: Mapping[str, FindingTally],
    root: Path,
    *,
    advertised: Mapping[str, bool | None],
) -> tuple[XrayArtifact, ...]:
    """The artifact list: each listed file with its size and findings; `advertised` is keyed by the file's path."""
    left_out = left_out_files(files, root)
    return tuple(
        XrayArtifact(
            path=relative_wire_path(item.path, root),
            kind=item.kind,
            scope=item.scope,
            plugin=item.plugin,
            label=item.label,
            memory_type=item.memory_type,
            linked=item.linked,
            findings=count_for(findings, item.path, root),
            actionable=is_actionable(item, root),
            tokens_est=file_tokens_est(real_path(item.path, root)),
            advertised=advertised.get(item.path),
            scopes=rule_scopes(item, root),
            excluded=left_out.get(item.path, FileLeftOut()),
        )
        for item in files
    )


def peek_text(item: ArtifactFile, root: Path) -> XrayPeek | None:
    """The text of a listed file cut at `PEEK_LIMIT` characters, whether it was cut, and the text split into its
    frontmatter block and what follows; None when the path is not a readable file."""
    path = Path(real_path(item.path, root))
    try:
        if not path.is_file():
            return None
        with path.open(encoding="utf-8", errors="replace") as handle:
            text = handle.read(PEEK_LIMIT + 1)
    except OSError:
        return None
    cut = text[:PEEK_LIMIT]
    block = frontmatter_block(cut)
    return XrayPeek(cut, len(text) > PEEK_LIMIT, None if block is None else block.text, strip_frontmatter(cut))
