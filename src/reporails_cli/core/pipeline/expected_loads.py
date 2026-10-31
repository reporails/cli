"""The instruction files Claude Code loads for a session in a folder, and the AGENTS.md files it skips."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from reporails_cli.core.discovery.agent_config import extract_patterns, load_config_file_types
from reporails_cli.core.discovery.agent_discovery import discover_from_config, discover_ungated, is_memory_recall_entry
from reporails_cli.core.discovery.exclusions import RunExclusions, load_run_exclusions
from reporails_cli.core.discovery.plugin_roots import entry_pattern, installed_plugin_roots
from reporails_cli.core.discovery.project_root import resolve_project_root
from reporails_cli.core.discovery.read_gates import AliasFile, SkippedFile, claude_agents_md_reads, gated_file_types
from reporails_cli.core.discovery.walk import safe_resolve, shared_dir_listings
from reporails_cli.core.eventbus.store import prune
from reporails_cli.core.mapper.inspect import SESSION_INVOCABLE_TYPES, FileRead, file_read_by, load_registry
from reporails_cli.core.mapper.labels import file_label
from reporails_cli.core.mapper.memory_index import is_linked, memory_type
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.config.bootstrap import get_xray_log_dir
from reporails_cli.core.platform.config.claude_settings import (
    LAUNCH_INSTRUCTION_FILE_TYPES,
    MODES_WITHOUT_LAUNCH_INSTRUCTIONS,
    claude_instruction_files_mode,
)
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_object
from reporails_cli.core.platform.dto.results import ProjectConfig
from reporails_cli.core.platform.utils.hook_config import hook_sites, read_hook_config
from reporails_cli.core.platform.utils.utils import strip_frontmatter

AGENT = "claude"


def expected_loads(target: Path, plugins: Sequence[tuple[str, Path]] | None = None) -> JsonObject:
    """The files Claude Code loads for a session in `target` (instruction and rule files, no config
    surfaces) with their file type, loading mode, precedence and display label (a memory topic file also
    its type and whether the memory index links it), the files a session can invoke (skills, agents,
    commands and hook configs, from every scope and every installed plugin), and the AGENTS.md files it skips.
    `plugins` are the installed plugin roots to list (`installed_plugin_roots`, whose error for a malformed
    record propagates); without them the installed plugins are read here."""
    root = resolve_project_root(target)
    prune(root)
    exclusions = load_run_exclusions(root, None, None)
    project_config = get_project_config(root)
    registry = load_registry()
    mode = claude_instruction_files_mode(root)
    with shared_dir_listings():
        files, read_instructions, switched_off = _loaded_files(exclusions, project_config, root, registry, mode)
        candidates = discover_ungated(
            root,
            AGENT,
            gated_file_types(AGENT),
            exclusions,
            project_config=project_config,
        )
        invocable = _invocable_files(
            exclusions, project_config, root, registry, installed_plugin_roots(root) if plugins is None else plugins
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
    return {
        "version": 1,
        "agent": AGENT,
        "root": str(safe_resolve(root)),
        "event_log_dir": str(get_xray_log_dir()),
        "files": files,
        "invocable": invocable,
        "skipped": skipped_out,
        "aliases": _alias_rows(reads.aliases),
    }


def _alias_rows(aliases: Sequence[AliasFile]) -> list[JsonValue]:
    """The `AGENTS.md` files whose text reaches Claude through a `CLAUDE.md` it reads, in path order."""
    return [
        {"path": str(item.path), "same_as": str(item.same_as), "how": item.how}
        for item in sorted(aliases, key=lambda a: a.path)
    ]


def _loaded_files(
    exclusions: RunExclusions, project_config: ProjectConfig, root: Path, registry: dict[str, JsonObject], mode: str
) -> tuple[list[JsonValue], dict[Path, str], dict[Path, str]]:
    """The non-empty instruction and rule files Claude Code loads (the user's own included), the instruction
    files among them, and the launch files the `instructionFiles` setting turns off (each with its
    file type)."""
    found = discover_from_config(root, AGENT, exclusions, project_config=project_config, repo_scoped=False)
    instruction, rules = (set(bucket) for bucket in found[:2]) if found is not None else (set(), set())
    files: list[JsonValue] = []
    read_instructions: dict[Path, str] = {}
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
            read_instructions[path] = read.loading
        files.append(_loaded_entry(path, root, read))
    return files, read_instructions, switched_off


def _loaded_entry(path: Path, root: Path, read: FileRead) -> JsonObject:
    """One loaded file: its type, loading, precedence and label; a memory topic file also carries
    its type and whether `MEMORY.md` links it."""
    topic = is_memory_recall_entry(read.file_type, path.name)
    declared = memory_type(path) if topic else None
    entry: JsonObject = {
        "path": str(path),
        "file_type": read.file_type,
        "loading": read.loading,
        "precedence": read.precedence,
        "label": file_label(read.file_type, path, relative_wire_path(str(path), root), memory_type=declared),
    }
    if topic:
        entry["memory_type"] = declared
        entry["linked"] = is_linked(path)
    return entry


def _invocable_files(
    exclusions: RunExclusions,
    project_config: ProjectConfig,
    root: Path,
    registry: dict[str, JsonObject],
    plugins: Sequence[tuple[str, Path]],
) -> list[JsonValue]:
    """The skill entry files, agents, commands and hook configs a session in `root` can invoke, from the project,
    the user, the managed settings folder and every installed, enabled plugin, each with its precedence, plugin
    id and label."""
    roots = [plugin_root for _, plugin_root in plugins]
    entries = extract_patterns(as_object(as_object(load_config_file_types(AGENT)).get("skills")), "entry_patterns")
    found: dict[Path, JsonValue] = {}
    for file_type in SESSION_INVOCABLE_TYPES:
        paths = discover_ungated(
            root,
            AGENT,
            (file_type,),
            exclusions,
            project_config=project_config,
            repo_scoped=False,
            installed_plugins=roots,
        )
        for path in paths:
            if path in found or exclusions.leaves_out(path):
                continue
            if file_type == "skills" and entry_pattern(path, root, entries, roots) is None:
                continue
            if file_type == "hooks" and not any(hook_sites(_hook_data(path))):
                continue
            read = file_read_by(AGENT, path, root, registry, roots)
            if read is None:
                continue
            plugin = next((plugin_id for plugin_id, plugin_root in plugins if path.is_relative_to(plugin_root)), None)
            wire = relative_wire_path(str(path), root)
            found[path] = {
                "path": str(path),
                "file_type": file_type,
                "precedence": read.precedence,
                "plugin": plugin,
                "label": file_label(file_type, path, wire, plugin=plugin),
            }
    return [found[path] for path in sorted(found)]


def _hook_data(path: Path) -> JsonValue:
    """The parsed hook config at `path` (nothing when it cannot be read)."""
    config = read_hook_config(path)
    return config.data if config is not None else None


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
