"""The instruction files Claude Code loads for a session in a folder, and the AGENTS.md files it skips."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import discover_from_config, discover_ungated
from reporails_cli.core.discovery.exclusions import RunExclusions, load_run_exclusions
from reporails_cli.core.discovery.project_root import resolve_project_root
from reporails_cli.core.discovery.read_gates import SkippedFile, claude_agents_md_reads, gated_file_types
from reporails_cli.core.discovery.walk import safe_resolve, shared_dir_listings
from reporails_cli.core.mapper.inspect import _load_registry, file_read_by
from reporails_cli.core.platform.config.bootstrap import get_xray_log_dir
from reporails_cli.core.platform.config.claude_settings import (
    LAUNCH_INSTRUCTION_FILE_TYPES,
    MODES_WITHOUT_LAUNCH_INSTRUCTIONS,
    claude_instruction_files_mode,
)
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.results import ProjectConfig
from reporails_cli.core.platform.utils.utils import strip_frontmatter

AGENT = "claude"


def expected_loads(target: Path) -> JsonObject:
    """The files Claude Code loads for a session in `target` (instruction and rule files, no config
    surfaces) with their file type, loading mode and precedence, and the AGENTS.md files it skips."""
    root = resolve_project_root(target)
    exclusions = load_run_exclusions(root, None, None)
    project_config = get_project_config(root)
    registry = _load_registry()
    mode = claude_instruction_files_mode(root)
    with shared_dir_listings():
        files, read_instructions, switched_off = _loaded_files(exclusions, project_config, root, registry, mode)
        candidates = discover_ungated(
            root,
            AGENT,
            gated_file_types(AGENT),
            exclusions.walk_dirs,
            project_config=project_config,
        )
    skipped = [SkippedFile(path, "setting_off", None) for path in switched_off]
    reads = claude_agents_md_reads([p for p in candidates if not exclusions.leaves_out(p)], root, read_instructions)
    skipped.extend(reads.skipped)
    skipped_out: list[JsonValue] = [
        {
            "path": str(item.path),
            "file_type": switched_off.get(item.path) or _file_type_of_skipped(item.path, root, registry),
            "reason": item.reason,
            "cause": None if item.cause is None else str(item.cause),
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
    exclusions: RunExclusions, project_config: ProjectConfig, root: Path, registry: dict[str, JsonObject], mode: str
) -> tuple[list[JsonValue], list[Path], dict[Path, str]]:
    """The non-empty instruction and rule files Claude Code loads (the user's own included), the instruction
    files among them, and the launch files the `instructionFiles` setting turns off (each with its
    file type)."""
    found = discover_from_config(root, AGENT, exclusions.walk_dirs, project_config=project_config, repo_scoped=False)
    instruction, rules = (set(bucket) for bucket in found[:2]) if found is not None else (set(), set())
    files: list[JsonValue] = []
    read_instructions: list[Path] = []
    switched_off: dict[Path, str] = {}
    for path in sorted(p for p in instruction | rules if not exclusions.leaves_out(p)):
        read = file_read_by(AGENT, path, root, registry)
        if read is None or _is_blank(path):
            continue
        if (
            mode in MODES_WITHOUT_LAUNCH_INSTRUCTIONS
            and read.file_type in LAUNCH_INSTRUCTION_FILE_TYPES
            and read.loading == "session_start"
            and read.precedence != "managed"
        ):
            switched_off[path] = read.file_type
            continue
        if path in instruction:
            read_instructions.append(path)
        files.append(
            {"path": str(path), "file_type": read.file_type, "loading": read.loading, "precedence": read.precedence}
        )
    return files, read_instructions, switched_off


def _is_blank(path: Path) -> bool:
    """Whether the file holds nothing but whitespace once its byte-order mark and frontmatter are
    removed; Claude Code sends nothing for it. A file that cannot be read stays listed."""
    try:
        return not strip_frontmatter(path.read_text(encoding="utf-8-sig")).strip()
    except (OSError, UnicodeDecodeError):
        return False


def _file_type_of_skipped(path: Path, root: Path, registry: dict[str, JsonObject]) -> str:
    read = file_read_by(AGENT, path, root, registry)
    return read.file_type if read is not None else "agents_md"
