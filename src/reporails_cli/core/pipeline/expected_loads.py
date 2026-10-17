"""The instruction files Claude Code loads for a session in a folder, and the AGENTS.md files it skips."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import discover_ungated
from reporails_cli.core.discovery.project_root import resolve_project_root
from reporails_cli.core.discovery.read_gates import SkippedFile, claude_agents_md_reads, gated_file_types
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.mapper.inspect import _load_registry, file_read_by
from reporails_cli.core.pipeline.mapping import ScopeDiscovery, discover_scope
from reporails_cli.core.platform.config.bootstrap import get_xray_log_dir
from reporails_cli.core.platform.config.claude_settings import (
    MODES_WITHOUT_PROJECT_INSTRUCTIONS,
    claude_instruction_files_mode,
)
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue

AGENT = "claude"

# Precedence scopes whose instruction files an organization-managed-only setting turns off.
_OWN_SCOPES = frozenset({"project", "user"})


def expected_loads(target: Path) -> JsonObject:
    """The files Claude Code loads for a session in `target` (instruction and rule files, no config
    surfaces) with their file type, loading mode and precedence, and the AGENTS.md files it skips."""
    root = resolve_project_root(target)
    scope = discover_scope(root, AGENT, None, scan_files=False)
    registry = _load_registry()
    mode = claude_instruction_files_mode(root)
    files, read_instructions, switched_off = _loaded_files(scope, root, registry, mode)
    skipped = [SkippedFile(path, "setting_off") for path in switched_off]
    exclusions = scope.exclusions
    candidates = discover_ungated(
        root,
        AGENT,
        gated_file_types(AGENT),
        exclusions.walk_dirs,
        project_config=get_project_config(root),
    )
    reads = claude_agents_md_reads([p for p in candidates if not exclusions.leaves_out(p)], root, read_instructions)
    skipped.extend(reads.skipped)
    skipped_out: list[JsonValue] = [
        {
            "path": str(item.path),
            "file_type": switched_off.get(item.path) or _file_type_of_skipped(item.path, root, registry),
            "reason": item.reason,
            "setting": mode,
        }
        for item in sorted(skipped, key=lambda s: s.path)
    ]
    aliases: list[JsonValue] = [
        {"path": str(item.path), "same_as": str(item.same_as)} for item in sorted(reads.aliases, key=lambda a: a.path)
    ]
    return {
        "version": 1,
        "agent": AGENT,
        "root": str(safe_resolve(root)),
        "event_log_dir": str(get_xray_log_dir()),
        "files": files,
        "skipped": skipped_out,
        "aliases": aliases,
    }


def _loaded_files(
    scope: ScopeDiscovery, root: Path, registry: dict[str, JsonObject], mode: str
) -> tuple[list[JsonValue], list[Path], dict[Path, str]]:
    """The files Claude Code loads among the ones discovery found, the instruction files among
    them, and the project and user instruction files the `instructionFiles` setting turns off
    (each with its file type)."""
    instruction = {p for agent in scope.filtered for p in agent.instruction_files}
    rules = {p for agent in scope.filtered for p in agent.rule_files}
    files: list[JsonValue] = []
    read_instructions: list[Path] = []
    switched_off: dict[Path, str] = {}
    for path in sorted(instruction | rules):
        read = file_read_by(AGENT, path, root, registry)
        if read is None:
            continue
        if path in instruction and mode in MODES_WITHOUT_PROJECT_INSTRUCTIONS and read.precedence in _OWN_SCOPES:
            switched_off[path] = read.file_type
            continue
        if path in instruction:
            read_instructions.append(path)
        files.append(
            {"path": str(path), "file_type": read.file_type, "loading": read.loading, "precedence": read.precedence}
        )
    return files, read_instructions, switched_off


def _file_type_of_skipped(path: Path, root: Path, registry: dict[str, JsonObject]) -> str:
    read = file_read_by(AGENT, path, root, registry)
    return read.file_type if read is not None else "agents_md"
