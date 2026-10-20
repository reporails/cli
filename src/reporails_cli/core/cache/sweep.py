"""One sweep for cache-like folders: drop units by age, by total size, or by count, oldest first.

A unit is the files sharing a ``unit_of`` key (each file alone by default); its age is its
newest file's mtime and it is deleted whole. Several processes may sweep one folder, so a file
that vanishes or cannot be removed is skipped and never raised to the caller.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class _Unit:
    mtime: float = 0.0
    size: int = 0
    files: list[Path] = field(default_factory=list)


def sweep(
    files: Iterable[Path],
    *,
    unit_of: Callable[[Path], str] | None = None,
    now: float = 0.0,
    max_age_s: float | None = None,
    max_bytes: int | None = None,
    max_units: int | None = None,
) -> None:
    """Delete whole units older than `max_age_s` seconds before `now`; then, oldest first, until the
    rest hold at most `max_bytes` and at most `max_units` units."""
    units: dict[str, _Unit] = {}
    for path in files:
        try:
            info = path.stat()
        except OSError:
            continue
        unit = units.setdefault(unit_of(path) if unit_of else str(path), _Unit())
        unit.mtime = max(unit.mtime, info.st_mtime)
        unit.size += info.st_size
        unit.files.append(path)
    ordered = sorted(units.values(), key=lambda u: u.mtime)
    if max_age_s is not None:
        for unit in [u for u in ordered if now - u.mtime > max_age_s]:
            _delete(unit)
            ordered.remove(unit)
    if max_bytes is not None:
        total = sum(u.size for u in ordered)
        while ordered and total > max_bytes:
            unit = ordered.pop(0)
            total -= unit.size
            _delete(unit)
    if max_units is not None:
        while len(ordered) > max_units:
            _delete(ordered.pop(0))


def _delete(unit: _Unit) -> None:
    for path in unit.files:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
