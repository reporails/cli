"""The change fingerprint of a `validate` scan: what a reply depends on, hashed."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from pathlib import Path

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.core.platform.adapters.api_key import DEFAULT_SERVER_URL, has_api_key
from reporails_cli.core.platform.config.bootstrap import (
    get_global_config_path,
    get_local_config_path,
    get_project_config_path,
)
from reporails_cli.core.platform.config.config import get_global_config
from reporails_cli.core.platform.config.credentials import credentials_path
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.interfaces.mcp.tools import _discover_files


def scan_inputs_base(scan_root: Path) -> str:
    """The part of the change fingerprint that needs a walk of `scan_root`.

    Covers every file the scan reads (instruction, rule and agent config files, found the
    same way the scan finds them), the project and user config files whether present or
    absent, and whether a key is available together with the tier and the server address. Only
    presence and tier of the sign-in are hashed, never a key value. Empty string when nothing
    is found.
    """

    # A long-running server keeps the detected-agent list between calls, so a file added or
    # removed (or an exclusion changed) would go unseen: detect afresh, and the run that
    # follows reuses this fresh list.
    clear_agent_cache()
    discovery = _discover_files(scan_root)
    scanned: list[Path] = [Path(f) for f in discovery[2]] if isinstance(discovery, tuple) else []
    if not scanned:
        return ""
    config_files = [
        get_project_config_path(scan_root),
        get_local_config_path(scan_root),
        get_global_config_path(),
        credentials_path(),
    ]
    parts = _stat_parts({*scanned, *config_files})
    tier = get_global_config().tier
    server = os.environ.get("AILS_SERVER_URL", "").strip().rstrip("/") or DEFAULT_SERVER_URL
    parts.append(f"signed_in={has_api_key()}:tier={tier}:server={server}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def _stat_parts(files: Iterable[Path]) -> list[str]:
    """One `path:size:mtime_ns:content-hash` line per file (`path:absent` when it cannot be
    read), sorted. The content is hashed too, so an edit that keeps a file's size and
    modification time is still seen."""
    parts: list[str] = []
    for f in sorted(set(files), key=str):
        try:
            st = f.stat()
            digest = hashlib.sha256(f.read_bytes()).hexdigest() if f.is_file() else ""
            parts.append(f"{f}:{st.st_size}:{st.st_mtime_ns}:{digest}")
        except OSError:
            parts.append(f"{f}:absent")
    return parts


def combine_scan_inputs(base: str, files: Iterable[Path]) -> str:
    """The change fingerprint: `base` plus the size, modification time and content of each of
    `files` (supporting and imported files a run mapped, or the target file),
    each in nanoseconds, so an edit inside one clock tick that changes the size, or that
    moves the time at all, is seen. Empty string when `base` is empty."""
    if not base:
        return ""
    return hashlib.sha256("\n".join([base, *_stat_parts(files)]).encode()).hexdigest()


def dependency_files(
    ruleset_map: RulesetMap | None, target: Path, scan_root: Path, payload: JsonObject | None
) -> list[Path]:
    """Every file a reply depends on beyond the scan's own list: the files the last run mapped,
    every file the last reply reported on (a skill's supporting files, imported files) and, for
    a file target, the target itself."""
    names = [r.path for r in ruleset_map.files] if ruleset_map is not None else []
    names += list(as_object(payload.get("files")) if payload is not None else ())
    files = [target] if target.is_file() else []
    for name in names:
        p = Path(name).expanduser()
        files.append(p if p.is_absolute() else scan_root / p)
    return files


def compute_scan_fingerprint(
    scan_root: Path, ruleset_map: RulesetMap | None, payload: JsonObject | None, target: Path
) -> tuple[str, str]:
    """Fingerprint every input of a `validate` reply, to detect changes between calls.

    Returns the walk's part (reused to restamp after a fresh run, with no second walk) and the
    full fingerprint.
    """
    base = scan_inputs_base(scan_root)
    return base, combine_scan_inputs(base, dependency_files(ruleset_map, target, scan_root, payload))
