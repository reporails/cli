"""Local preflight gates and server 4xx body parsing.

Pure decision functions that turn a projected payload or a server error body
into a `FunnelError`. The preflight gates cover only the absolute caps
(atoms, files), checked locally before anything is uploaded. Limits that depend
on the plan (byte cap, rate cap) are reported by the server and not checked here.
"""

from __future__ import annotations

import json
import logging

from reporails_cli.core.platform.contract.json_value import WireObject, wire_list
from reporails_cli.core.platform.dto.diagnostics import (
    DEFAULT_RETRY_AFTER_S,
    ENTITLED_TIERS,
    KNOWN_ERRORS,
    RETRYABLE_ERRORS,
    FunnelError,
)
from reporails_cli.core.platform.policy.exclusion import FolderValue, parse_folder_value

logger = logging.getLogger(__name__)


UNIVERSAL_ATOM_CAP = 10_000
WIRE_MAX_FILES = 500

# How many of the densest top-level folders a refusal names.
_DENSE_DIRS_SHOWN = 5

# The route search: how many candidate folder names it weighs, and the most names it combines.
_ROUTE_POOL = 16
_ROUTE_MAX_NAMES = 4

# A 5xx reply is parsed only when it names a failure that clears on its own.
_RETRYABLE_STATUSES = (503, 504)

_CONTACT_SUFFIXES = {
    "payload_too_large": "payload",
    "atom_cap_exceeded": "atoms",
}


def _preflight_url(error: str, tier: str) -> str:
    """Contact-form URL for an entitled session that hit an absolute cap.

    Gated on the shared entitled-tier set, not on the single string `"pro"` — a
    `team` session is a paying session and must get the same contact form, not
    the unentitled upgrade CTA.
    """
    if tier not in ENTITLED_TIERS or error not in _CONTACT_SUFFIXES:
        return ""
    return f"https://reporails.com/contact/{_CONTACT_SUFFIXES[error]}?utm_source=cli"


def parse_retry_after(raw: str | None) -> int | None:
    """The whole seconds in a `Retry-After` header value; None when absent or not a number."""
    text = (raw or "").strip()
    return int(text) if text.isdigit() else None


def parse_error_body(status_code: int, body_text: str, retry_after: str | None = None) -> FunnelError | None:
    """Parse a 4xx body, or a 503/504 body naming a busy or slow server, into a FunnelError.

    `retry_after` is the reply's `Retry-After` header, in seconds. Returns None for a non-4xx
    status and for any other 5xx reply, which is reported as a plain HTTP error.
    """
    retryable_status = status_code in _RETRYABLE_STATUSES
    if not (400 <= status_code < 500 or retryable_status):
        return None
    try:
        body = json.loads(body_text)
    except (json.JSONDecodeError, ValueError):
        logger.debug("Non-JSON %d response body: %r", status_code, body_text[:200])
        return None if retryable_status else _unknown_error(status_code, "")
    if not isinstance(body, dict):
        logger.debug("Unexpected %d response shape: %r", status_code, body_text[:200])
        return None if retryable_status else _unknown_error(status_code, "")
    error = body.get("error", "")
    if not (isinstance(error, str) and error) and isinstance(body.get("detail"), str):
        error = body["detail"]
    if retryable_status and error not in RETRYABLE_ERRORS:
        return None
    if error not in KNOWN_ERRORS:
        message = str(body.get("message", "")) or f"HTTP {status_code} ({error or 'unrecognized'})"
        return _unknown_error(status_code, message, str(body.get("tier", "")))
    reset_in = int(body.get("reset_in") or 0)
    if error in RETRYABLE_ERRORS:
        header = parse_retry_after(retry_after) or 0
        reset_in = reset_in or header or DEFAULT_RETRY_AFTER_S
    return FunnelError(
        error=error,
        tier=str(body.get("tier", "")),
        limit=int(body.get("limit") or body.get("limit_bytes") or 0),
        size=int(body.get("size") or body.get("atoms") or body.get("bytes") or 0),
        files=int(body.get("files") or 0),
        reset_in=reset_in,
        upgrade_url=str(body.get("upgrade_url", "")),
        support_url=str(body.get("support_url", "")),
        message=str(body.get("message", "")),
        status=status_code,
    )


def _unknown_error(status_code: int, message: str, tier: str = "") -> FunnelError:
    """The catch-all error for a reply whose body names no known token; it renders the bug-report link."""
    return FunnelError(
        error="unknown_error",
        tier=tier,
        message=message or f"Diagnostics server returned HTTP {status_code}",
        status=status_code,
    )


def _is_project_relative(path: str) -> bool:
    """True for a project-relative posix path; `~/...` and absolute paths lie outside the project."""
    return bool(path) and not path.startswith(("~/", "/")) and ":" not in path.split("/", 1)[0]


def _atoms_per_file(payload: WireObject) -> dict[str, int]:
    """Atom count per project-relative file path; files outside the project are left out."""
    files = wire_list(payload.get("files", []))
    counts: dict[str, int] = {}
    for atom in wire_list(payload.get("atoms", [])):
        index = atom.get("fi") if isinstance(atom, dict) else None
        if not isinstance(index, int) or not 0 <= index < len(files):
            continue
        entry = files[index]
        path = str(entry.get("path", "")) if isinstance(entry, dict) else ""
        if _is_project_relative(path):
            counts[path] = counts.get(path, 0) + 1
    return counts


def _shown_dirs(per_file: dict[str, int], total: int) -> tuple[tuple[str, int], ...]:
    """The five densest folder paths with their atom counts.

    Starts at the project root and descends through any folder holding at least 90% of the
    project's atoms (while it has subfolders), then lists the densest subfolders at that level.
    """
    prefix: tuple[str, ...] = ()
    while True:
        level: dict[tuple[str, ...], int] = {}
        for path, n in per_file.items():
            parts = tuple(path.split("/"))
            if len(parts) > len(prefix) + 1 and parts[: len(prefix)] == prefix:
                key = parts[: len(prefix) + 1]
                level[key] = level.get(key, 0) + n
        heavy = [key for key, n in level.items() if n * 10 >= total * 9]
        if not heavy:
            break
        deeper = any(
            len(p.split("/")) > len(heavy[0]) + 1 and tuple(p.split("/"))[: len(heavy[0])] == heavy[0] for p in per_file
        )
        if not deeper:
            break
        prefix = heavy[0]
    ranked = sorted(level.items(), key=lambda item: (-item[1], item[0]))
    return tuple(("/".join(key), n) for key, n in ranked[:_DENSE_DIRS_SHOWN])


def _dense_dirs_and_route(payload: WireObject, cap: int) -> tuple[tuple[tuple[str, int], ...], tuple[str, ...]]:
    """The densest folder paths with their atom counts, and the folder names to leave out to get under `cap`.

    A name removes every file with that name anywhere in its path (the way `--exclude-dirs`
    works). The route keeps as much checked as possible: the names, one or several, whose combined
    removal is the smallest that covers the excess. It is empty when no set of names brings the
    project under the cap.
    """
    per_file = _atoms_per_file(payload)
    total = len(wire_list(payload.get("atoms", [])))
    return _shown_dirs(per_file, total), _route(_files_by_name(per_file), per_file, total - cap)


def _name_candidate(part: str) -> FolderValue | None:
    """The folder name `--exclude-dirs` would read `part` as; `None` when it names no folder, a path, or is refused."""
    try:
        value = parse_folder_value(part, ())
    except ValueError:
        return None
    return value if value is not None and not value.anchored else None


def _files_by_name(per_file: dict[str, int]) -> dict[str, set[str]]:
    """Each folder name -> the files `--exclude-dirs <name>` leaves out (the name anywhere in the path).

    The names are the folder segments of the paths that `--exclude-dirs` accepts as a single name;
    each is tried once against each distinct folder it appears in.
    """
    in_folder: dict[str, list[str]] = {}
    for path in per_file:
        in_folder.setdefault(path.rpartition("/")[0], []).append(path)
    parsed: dict[str, FolderValue | None] = {}
    by_name: dict[str, set[str]] = {}
    for folder, paths in in_folder.items():
        for part in dict.fromkeys(folder.split("/")):
            if part not in parsed:
                parsed[part] = _name_candidate(part)
            candidate = parsed[part]
            if candidate is not None and candidate.holds(folder):
                by_name.setdefault(candidate.text, set()).update(paths)
    return by_name


def _route(by_name: dict[str, set[str]], per_file: dict[str, int], excess: int) -> tuple[str, ...]:
    """The folder names (in name order) whose combined removal is the smallest that takes out `excess` atoms.

    The search is exact over a bounded set: names whose own removal is below the smallest single
    sufficient name's (every name when none suffices), the 16 largest of those, in sets of up to
    four. Ties go to fewer names, then name order. When that search finds no cover, names are added
    by the most atoms not already removed until the excess is met. Empty when no set of names covers it.
    """

    def weight(paths: set[str]) -> int:
        return sum(per_file[path] for path in paths)

    removal = {name: weight(paths) for name, paths in by_name.items()}
    if weight(set().union(*by_name.values())) < excess:
        return ()
    single = min(((n, name) for name, n in removal.items() if n >= excess), default=None)
    pool = [name for name, n in removal.items() if single is None or n < single[0]]
    pool = sorted(sorted(pool, key=lambda name: (-removal[name], name))[:_ROUTE_POOL], key=str)
    best: tuple[int, int, tuple[str, ...]] | None = (single[0], 1, (single[1],)) if single else None

    def search(start: int, chosen: tuple[str, ...], covered: set[str], removed: int) -> None:
        nonlocal best
        for i in range(start, len(pool)):
            name = pool[i]
            fresh = by_name[name] - covered
            total = removed + weight(fresh)
            if best is not None and total > best[0]:
                continue
            names = (*chosen, name)
            if total >= excess:
                key = (total, len(names), names)
                if best is None or key < best:
                    best = key
            elif len(names) < _ROUTE_MAX_NAMES:
                search(i + 1, names, covered | fresh, total)

    search(0, (), set(), 0)
    if best is not None:
        return best[2]
    return _greedy_route(by_name, per_file, excess)


def _greedy_route(by_name: dict[str, set[str]], per_file: dict[str, int], excess: int) -> tuple[str, ...]:
    """Names added by the most atoms not already removed until `excess` atoms go; empty when they never do."""
    chosen: list[str] = []
    covered: set[str] = set()
    left = excess
    while left > 0:
        gain, best = min(
            (
                (sum(per_file[path] for path in paths - covered), name)
                for name, paths in by_name.items()
                if name not in chosen
            ),
            key=lambda item: (-item[0], item[1]),
        )
        if gain <= 0:
            return ()
        chosen.append(best)
        covered |= by_name[best]
        left -= gain
    return tuple(chosen)


def preflight_oversized(
    payload: WireObject,
    has_api_key: bool,
) -> FunnelError | None:
    """Local check on universal absolute caps (atoms, files)."""
    presumed_tier = "pro" if has_api_key else "anonymous"
    n_atoms = len(wire_list(payload.get("atoms", [])))
    if n_atoms > UNIVERSAL_ATOM_CAP:
        dense_dirs, exclude_route = _dense_dirs_and_route(payload, UNIVERSAL_ATOM_CAP)
        return FunnelError(
            error="atom_cap_exceeded",
            tier=presumed_tier,
            limit=UNIVERSAL_ATOM_CAP,
            size=n_atoms,
            files=len(wire_list(payload.get("files", []))),
            upgrade_url=_preflight_url("atom_cap_exceeded", presumed_tier),
            dense_dirs=dense_dirs,
            exclude_route=exclude_route,
        )
    n_files = len(wire_list(payload.get("files", [])))
    if n_files > WIRE_MAX_FILES:
        # A separate token from `payload_too_large`: the file-count cap is the same
        # for every plan, so it carries no upgrade or contact-form link.
        return FunnelError(
            error="file_cap_exceeded",
            tier=presumed_tier,
            limit=WIRE_MAX_FILES,
            size=n_files,
            files=n_files,
            upgrade_url="",
        )
    return None
