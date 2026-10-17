"""The instruction files Claude Code loads for a session in a folder, and the AGENTS.md files it skips."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import discover_unread_candidates
from reporails_cli.core.discovery.project_root import resolve_project_root
from reporails_cli.core.discovery.read_gates import claude_agents_md_reads, gated_file_types
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.mapper.inspect import _load_registry, file_read_by
from reporails_cli.core.pipeline.mapping import discover_scope
from reporails_cli.core.platform.config.bootstrap import get_xray_log_dir
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue

AGENT = "claude"


def expected_loads(target: Path) -> JsonObject:
    """The files Claude Code loads for a session in `target` (instruction and rule files, no config
    surfaces) with their file type, loading mode and precedence, and the AGENTS.md files it skips."""
    root = resolve_project_root(target)
    scope = discover_scope(root, AGENT, None, scan_files=False)
    registry = _load_registry()
    paths = sorted({p for agent in scope.filtered for p in (*agent.instruction_files, *agent.rule_files)})
    files: list[JsonValue] = []
    for path in paths:
        read = file_read_by(AGENT, path, root, registry)
        if read is not None:
            files.append(
                {
                    "path": str(path),
                    "file_type": read.file_type,
                    "loading": read.loading,
                    "precedence": read.precedence,
                }
            )
    exclusions = scope.exclusions
    candidates = discover_unread_candidates(
        root, AGENT, gated_file_types(AGENT), exclusions.walk_dirs if exclusions else frozenset()
    )
    reads = claude_agents_md_reads([p for p in candidates if exclusions is None or not exclusions.leaves_out(p)], root)
    skipped: list[JsonValue] = [
        {
            "path": str(item.path),
            "file_type": _file_type_of_skipped(item.path, root, registry),
            "reason": item.reason,
            "setting": reads.mode,
        }
        for item in sorted(reads.skipped, key=lambda s: s.path)
    ]
    return {
        "version": 1,
        "agent": AGENT,
        "root": str(safe_resolve(root)),
        "event_log_dir": str(get_xray_log_dir()),
        "files": files,
        "skipped": skipped,
    }


def _file_type_of_skipped(path: Path, root: Path, registry: dict[str, JsonObject]) -> str:
    read = file_read_by(AGENT, path, root, registry)
    return read.file_type if read is not None else "agents_md"
