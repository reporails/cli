"""Surface-agnostic ruleset-map building + agent-filter resolution shared by CLI and MCP.

The ``ails check`` flow and the MCP ``validate`` tool each resolved the mapper daemon and
narrowed the discovered agent set in their own way, so the two surfaces mapped against
different paths (warm daemon vs cold in-process) and discovered against different agent
lists (resolved-and-filtered vs raw-detected). This module carries the one implementation
both surfaces call: ``map_instruction_files`` consults the whole-map cache first, resolves
the daemon, and falls back to in-process mapping; ``resolve_agent_filters`` narrows the
detected agents to the effective, exclude-filtered set; ``apply_generic_scan`` folds
``@``-import-reached files into the scored set; ``discover_scope`` runs the agent detection,
filter resolution and file discovery of one scan as a single pass that reads each directory
once. Display concerns (spinner, stderr) stay with the caller via the optional ``progress``
callback.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, NamedTuple


class ScopeDiscovery(NamedTuple):
    """What one discovery pass found at a scan root."""

    detected: list[Any]
    effective_agent: str
    assumed: bool
    mixed: bool
    filtered: list[Any]
    files: list[Path]


def discover_scope(
    target: Path,
    agent: str,
    exclude_dirs: list[str] | None,
    exclude_files: list[str] | None = None,
    *,
    scan_files: bool = True,
) -> ScopeDiscovery:
    """Detect the agents at ``target``, resolve the effective agent and its exclude-filtered
    agent set, and (unless ``scan_files`` is false) list the files a whole-project scan covers.

    Both surfaces call this, so ``ails check`` and MCP ``validate`` discover the same way and
    share one directory listing across the many file-name walks of the pass.
    """
    from reporails_cli.core.discovery.agents import detect_agents, get_all_scannable_files
    from reporails_cli.core.discovery.walk import shared_dir_listings

    with shared_dir_listings():
        detected = detect_agents(target)
        effective, assumed, mixed, filtered = resolve_agent_filters(
            agent, detected, target, exclude_dirs, exclude_files
        )
        files = get_all_scannable_files(target, agents=filtered) if scan_files else []
    return ScopeDiscovery(detected, effective, assumed, mixed, filtered, files)


def resolve_agent_filters(
    agent: str,
    all_detected: list[Any],
    target: Path,
    exclude_dirs: list[str] | None,
    exclude_files: list[str] | None = None,
) -> tuple[str, bool, bool, list[Any]]:
    """Resolve agent selection and filter detected agents. Returns ``(agent, assumed, mixed, filtered)``.

    ``filtered`` is the DISCOVERY scope, not a rule-selection narrowing: an explicit
    ``agent`` narrows it to that one agent's own files (unchanged, existing behavior).
    Auto-detect never narrows it -- it is every detected agent's own files, the generic
    agent's (`AGENTS.md`, `.agents/`) beside the named agents', regardless of how many stay
    distinctive, so a cross-read-only agent losing distinctiveness never drops a file
    discovery reached.
    Callers route each file to the right ruleset via
    ``core.discovery.agents.partition_by_native_owner`` (the DISTINCTIVE agent that
    natively owns a file, or the core rule set when none does), not via ``filtered``.
    """
    from reporails_cli.core.discovery.agents import (
        detect_single_agent,
        filter_agents_by_exclude_dirs,
        filter_agents_by_exclude_files,
        filter_agents_by_id,
        resolve_agent,
    )

    explicit = bool(agent)
    agent, assumed, mixed = resolve_agent(agent, all_detected, target)
    effective = agent if agent else "generic"
    if explicit:
        filtered = filter_agents_by_id(all_detected, effective)
        if not filtered:
            filtered = [d for d in (detect_single_agent(target, effective),) if d is not None]
    else:
        filtered = list(all_detected)
    filtered = filter_agents_by_exclude_dirs(filtered, target, frozenset(exclude_dirs or ()))
    filtered = filter_agents_by_exclude_files(filtered, target, exclude_files)
    return effective, assumed, mixed, filtered


def apply_generic_scan(
    target: Path,
    instruction_files: list[Path],
    agent: str,
    generic_scanning: bool,
    exclude_files: list[str] | None = None,
) -> tuple[list[Path], dict[str, str]]:
    """Fold ``@``-import-reached (generic) files into the scored set; classify all generic-scanned files.

    Mirrors the CLI check flow's generic-scan fold (`interfaces/cli/check_support.py`'s
    file-type classification plus the exclude-glob drop applied alongside it) so both
    surfaces score the same file set under ``generic_scanning: true``. Returns
    ``(import_extra, file_type_by_path)``:

    - ``import_extra`` -- ``@``-import-reached files (``file_type == "generic"``, eagerly
      auto-loaded) to ADD to the mapped + server-scored set so they earn an Imported quality
      score. Markdown-``referenced`` files are deliberately excluded: the harness never loads
      them, so folding them into the score would be a false signal -- they stay lint-only.
      Entries matching an ``exclude_files`` glob are dropped.
    - ``file_type_by_path`` -- normalized path -> file_type for ALL generic-scanned files
      (generic + referenced), so the display routes them to the Imported surface / Referenced
      panel.

    No-op (``([], {})``) when generic scanning is off.
    """
    if not generic_scanning:
        return [], {}
    from reporails_cli.core.classify import classify_files, load_file_types
    from reporails_cli.core.discovery.walk import shared_dir_listings
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    try:
        file_types = load_file_types(agent, project_root=target)
        with shared_dir_listings():
            classified = classify_files(target, list(instruction_files), file_types, generic_scanning=True)
    except (OSError, ValueError):
        return [], {}

    ft_by_path = {normalize_finding_path(str(cf.path), target): cf.file_type for cf in classified}
    seen = {normalize_finding_path(str(p), target) for p in instruction_files}
    import_extra = [
        cf.path
        for cf in classified
        if cf.file_type == "generic" and normalize_finding_path(str(cf.path), target) not in seen
    ]
    if import_extra and exclude_files:
        from reporails_cli.core.platform.utils.utils import matches_any_glob

        import_extra = [f for f in import_extra if not matches_any_glob(f, exclude_files, target)]
    return import_extra, ft_by_path


def agent_file_pairs(
    instruction_files: list[Path],
    filter_agents: list[Any],
    target: Path,
    *,
    explicit: bool,
    effective_agent: str,
) -> list[tuple[str, list[Path]]]:
    """The ``(agent_id, its own files)`` pairs a caller's rule-running functions iterate
    over -- shared by the CLI check flow and MCP ``validate`` so both surfaces score
    IDENTICAL ``(rule, file, line)`` triples for the same tree (``validate`` is the paid
    path; it must never diverge from ``ails check``).

    An explicit ``agent`` (``--agent`` / ``default_agent``) runs over the WHOLE scoped file
    set unchanged -- the caller asked for that one agent's perspective specifically.
    Auto-detect partitions the full scoped set (never narrowed) by native ownership via
    ``core.discovery.agent_discovery.partition_by_native_owner``: a file a
    currently-distinctive agent natively owns runs that agent's own rules; a file no
    distinctive agent natively owns (a shared cross-agent standard, a nested ``AGENTS.md``
    no agent's own namespace claims) runs the core rule set (``agent=""``), exactly as a
    plain single-agent project's own unclaimed files would.
    """
    if explicit:
        return [(effective_agent, list(instruction_files))]

    from reporails_cli.core.discovery.agent_discovery import partition_by_native_owner

    owner_by_path = partition_by_native_owner(filter_agents, target)
    pairs: dict[str, list[Path]] = {}
    for f in instruction_files:
        owner = owner_by_path.get(f.as_posix(), "generic")
        pairs.setdefault("" if owner == "generic" else owner, []).append(f)
    return list(pairs.items())


def stamp_file_agents(ruleset_map: Any, detected_agents: list[Any] | None, target: Path) -> None:
    """Correct each file record's ``agent`` to the file's DISTINCTIVE native owner, or to
    ``"generic"`` when no currently-distinctive agent natively owns it.

    ``core/mapper/inspect.py``'s per-file registry match classifies every file against the
    FULL agent registry independently of which agent(s) discovery resolved for this run, and
    a marker several agents share (root ``AGENTS.md``) ties-break on registry declaration
    order rather than the project's real agent -- a Codex project with an
    ``AGENTS.md`` + ``.codex/`` marker can come back attributed to Antigravity. ``detected_agents``
    is every non-generic agent discovery detected (``resolve_agent_filters``'s ``filtered``,
    the whole-scope list, not narrowed to one agent) -- ``partition_by_native_owner`` is the
    authoritative per-file answer, so every claimed file's record ``agent`` is overwritten to
    match it, in place. A no-op when ``detected_agents`` is falsy (nothing to stamp from).
    """
    from reporails_cli.core.discovery.agent_discovery import partition_by_native_owner
    from reporails_cli.core.platform.dto.ruleset import RulesetMap as _RulesetMap

    if not detected_agents or not isinstance(ruleset_map, _RulesetMap):
        return
    owner_by_path = partition_by_native_owner(detected_agents, target)
    for record in ruleset_map.files:
        owner = owner_by_path.get(record.path)
        if owner is not None:
            record.agent = owner


def _apply_run_context(ruleset_map: Any, filtered_agents: list[Any] | None, target: Path) -> None:
    """Record skill membership for the run's agents, then stamp each file's owning agent."""
    from reporails_cli.core.mapper.skills import record_skills

    agents = [a.agent_type.id for a in filtered_agents or () if a.agent_type.id != "generic"]
    record_skills(ruleset_map, agents, target)
    stamp_file_agents(ruleset_map, filtered_agents, target)


def map_instruction_files(
    target: Path,
    instruction_files: list[Path],
    *,
    progress: Callable[[str], None] | None = None,
    spawn_daemon: bool = True,
    filtered_agents: list[Any] | None = None,
) -> Any:
    """Map instruction files via the whole-map cache, else the daemon, else in-process.

    Checks the whole-map cache FIRST, before any daemon resolution -- a byte-identical cached
    map (file set + model + schema + segmentation identity all match) returns straight off
    disk, skipping the daemon round-trip AND the daemon-resolution
    step itself. Only on a cache miss does it resolve the daemon and map via it (with an
    in-process fallback), then stores the result. ``progress`` receives status strings (daemon
    state, "Loading tools...") so a caller can drive a spinner; it defaults to a no-op for
    headless surfaces like MCP.

    ``spawn_daemon`` controls whether a cache-miss may fork a new daemon process. The CLI
    (default ``True``) keeps its eager-warmup spawn behavior. A caller that must not fork from
    inside its own process (the MCP server, running inside a multi-threaded asyncio event
    loop) passes ``spawn_daemon=False``: it attaches to an already-running daemon when one
    answers a ping, else maps in-process directly -- it never calls ``ensure_daemon`` /
    ``start_daemon``.

    ``filtered_agents`` is discovery's resolved per-agent file ownership (the same ``filtered``
    list ``resolve_agent_filters`` returns) -- when given, every returned file record's
    ``agent`` is corrected to match it (see ``stamp_file_agents``), regardless of whether the
    map came from cache, the daemon, or in-process, so cold, warm, daemon and this surface
    agree on attribution.
    """
    from reporails_cli.core.cache.full_map_cache import FullMapCache, compute_identity
    from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir
    from reporails_cli.core.platform.config.config import get_project_config

    emit = progress if progress is not None else (lambda _msg: None)

    full_cache = FullMapCache(get_global_cache_dir())
    identity = compute_identity(
        list(instruction_files), root=target, segmentation=get_project_config(target).mapper.segmentation
    )
    cached = full_cache.get(identity)
    if cached is not None:
        _apply_run_context(cached, filtered_agents, target)
        return cached

    daemon_status = _resolve_daemon(emit, spawn_daemon=spawn_daemon)

    ruleset_map = _map_via_daemon_or_process(
        daemon_status, list(instruction_files), target, get_project_config(target).mapper, emit
    )
    if ruleset_map is not None:
        full_cache.put(identity, ruleset_map)  # the map as mapped; a later run with other agents decides again
        _apply_run_context(ruleset_map, filtered_agents, target)
    return ruleset_map


def _resolve_daemon(emit: Callable[[str], None], *, spawn_daemon: bool = True) -> Any:
    """Attach to (or, when allowed, start) the global mapper daemon; return its status.

    When ``spawn_daemon`` is False this only ever attaches to an already-running daemon
    (a live ping) -- it never calls ``ensure_daemon``/``start_daemon``, so it cannot fork
    a child process from inside a caller (like the MCP server) that must not fork.
    """
    if not spawn_daemon:
        from reporails_cli.core.mapper.daemon import is_daemon_running, retire_daemon
        from reporails_cli.core.mapper.daemon_client import DaemonStatus, ping, runs_older_code, serves_this_code

        try:
            pong = ping() if is_daemon_running() else None
            attached = serves_this_code(pong)
            if pong is not None and not attached and runs_older_code(pong):
                # Left over from an older version: retire it so it does not linger; the next
                # check that may start a daemon starts this version's.
                retire_daemon(pong.get("pid"))
        except OSError:
            attached = False
        if not attached:
            emit("Starting Reporails...")
            return DaemonStatus.UNAVAILABLE
        return DaemonStatus.ATTACHED

    from reporails_cli.core.mapper.daemon_client import DaemonStatus, ensure_daemon

    try:
        status = ensure_daemon(emit=emit)
    except (ImportError, OSError):
        return DaemonStatus.UNAVAILABLE

    if status == DaemonStatus.STARTED:
        emit("Reporails ready")
    elif status == DaemonStatus.STARTING:
        emit("Warming up...")
    elif status == DaemonStatus.UNAVAILABLE:
        emit("Starting Reporails...")
    return status


def _map_via_daemon_or_process(
    daemon_status: Any, files: list[Path], target: Path, mapper_cfg: Any, emit: Callable[[str], None]
) -> Any:
    """Map via the daemon when attached, else in-process with sub-logger noise quieted."""
    from reporails_cli.core.mapper.daemon_client import DaemonStatus, map_ruleset_via_daemon

    if daemon_status in (DaemonStatus.ATTACHED, DaemonStatus.STARTED, DaemonStatus.STARTING):
        # STARTING: the daemon's socket is up but its models are still warming. The daemon-side
        # handler blocks on `warmup_done` before serving a map (daemon._dispatch), so routing the
        # map to it waits once and loads the models once — instead of mapping in-process here (a
        # second, redundant model load) while the freshly-spawned daemon warms a copy it never
        # serves for this run. In-process stays the fallback below only when the daemon is
        # UNAVAILABLE or the round-trip returns None.
        ruleset_map = map_ruleset_via_daemon(files, target, progress=emit)
        if ruleset_map is not None:
            return ruleset_map
        emit("Restarting Reporails...")

    emit("Loading tools...")
    return _map_in_process(files, target, mapper_cfg.segmentation, progress=emit)


def _map_in_process(
    instruction_files: list[Path],
    root: Path,
    segmentation: str,
    progress: Callable[[str], None] | None = None,
) -> Any:
    """Run the mapper in-process, quieting known-noisy loader logs. Returns RulesetMap or None.

    ``root`` is the project root and is REQUIRED: every file's ``loading`` / ``scope`` /
    ``globs`` / ``agent`` is derived from its path relative to it, so a root that is not the
    project root silently reclassifies nested surfaces (a `.cursor/rules/*.mdc` matched
    against its own parent directory resolves to nothing and degrades to the generic
    session-start default).

    The loader libraries' log level is lowered for the call's duration only, and restored
    afterwards; the process's stderr is never swapped, so this function's own "mapper
    unavailable" warning always reaches the real logging handler, and concurrent callers
    on other threads lose no output.

    Models load lazily on first use: when the map cache is mostly warm they are never
    loaded, so a single check stays fast.
    """
    import logging

    noisy_loggers = ("sentence_transformers", "transformers", "huggingface_hub", "reporails_cli.core.mapper")
    previous_levels = {name: logging.getLogger(name).level for name in noisy_loggers}
    for name in noisy_loggers:
        logging.getLogger(name).setLevel(logging.ERROR)
    try:
        from reporails_cli.core.mapper import map_ruleset
        from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir

        return map_ruleset(
            list(instruction_files),
            root=root,
            cache_dir=get_global_cache_dir(),
            segmentation=segmentation,
            progress=progress,
        )
    except (ImportError, RuntimeError) as exc:
        # The user-visible line never repeats `exc` verbatim; the full exception
        # still reaches DEBUG for a `-v`/log-file diagnosis.
        logging.getLogger(__name__).warning("In-process mapper unavailable; content checks skipped")
        logging.getLogger(__name__).debug("In-process mapper unavailable: %s", exc)
        return None
    finally:
        for name, level in previous_levels.items():
            logging.getLogger(name).setLevel(level)
