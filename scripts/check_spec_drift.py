#!/usr/bin/env python3
"""Report subsystems whose source has been modified more recently than their spec.

Reads a project backbone config (path resolved at runtime) for a `subsystems:`
section, then for each entry compares the newest mtime across its listed
source modules against the mtime of the design spec. When source is newer than
spec by more than `STALE_THRESHOLD_DAYS`, the spec is flagged as potentially
stale — its description of invariants, data shapes, or pipeline stages may no
longer match reality.

This is a heuristic. mtime-newer does not prove a public-shape change happened;
it only flags candidates for review.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BACKBONE = ROOT / ".ails" / "backbone.yml"

# Tolerate up to one calendar day of drift before flagging — source edits
# routinely happen without invariant changes.
STALE_THRESHOLD_DAYS = 1


def _newest_mtime(paths: list[Path]) -> float:
    """Return the max mtime across paths, recursing into directories."""
    newest = 0.0
    for p in paths:
        if not p.exists():
            continue
        if p.is_dir():
            for child in p.rglob("*"):
                if child.is_file() and "__pycache__" not in child.parts:
                    newest = max(newest, child.stat().st_mtime)
        else:
            newest = max(newest, p.stat().st_mtime)
    return newest


def main() -> int:
    if not BACKBONE.exists():
        print("spec-drift: no backbone config; skipped")
        return 0
    try:
        backbone = yaml.safe_load(BACKBONE.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        print(f"spec-drift: backbone config failed to parse: {exc}", file=sys.stderr)
        return 2
    subs = backbone.get("subsystems") or {}
    if not isinstance(subs, dict) or not subs:
        print("spec-drift: no subsystems declared; nothing to check")
        return 0

    threshold_seconds = STALE_THRESHOLD_DAYS * 86400
    stale: list[tuple[str, str, float]] = []

    for name, entry in subs.items():
        if not isinstance(entry, dict):
            continue
        spec_rel = entry.get("spec")
        mods = entry.get("modules") or []
        if not spec_rel or not mods:
            continue
        spec_path = ROOT / spec_rel
        if not spec_path.exists():
            continue
        spec_mtime = spec_path.stat().st_mtime
        module_paths = [ROOT / m for m in mods if isinstance(m, str)]
        source_mtime = _newest_mtime(module_paths)
        if source_mtime == 0.0:
            continue
        drift_seconds = source_mtime - spec_mtime
        if drift_seconds > threshold_seconds:
            stale.append((name, spec_rel, drift_seconds / 86400))

    if not stale:
        print(f"spec-drift: {len(subs)} subsystems, no specs older than source beyond {STALE_THRESHOLD_DAYS}d threshold")
        return 0

    print(f"spec-drift: {len(stale)} subsystem(s) with potentially stale specs:")
    for name, spec_rel, drift_days in sorted(stale, key=lambda t: -t[2]):
        print(f"  - {name}: {spec_rel} is {drift_days:.1f}d older than its newest source module")
    print("\nReview each listed spec and update if the change altered public shape.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
