#!/usr/bin/env python3
"""Validate the project's design-spec set against its declared subsystems.

Reads a project backbone config (path resolved at runtime) for a `subsystems:`
section. Three checks:

- **coverage**: every declared subsystem points at an existing spec file.
- **shape**: each spec has an H1 title, fits within a line-count budget, and is
  not a stub.
- **co-location**: each subsystem's listed source modules cluster under a single
  parent directory. Scattering across multiple parents signals that the
  subsystem boundary in the doc is sharper than the code structure — consider
  consolidating the modules under a named subpackage.

Exits 0 with a "skipped" message if no backbone config is present.
"""

from __future__ import annotations

import sys
from os.path import commonpath
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BACKBONE = ROOT / ".ails" / "backbone.yml"

# Shape budget. Tuned to the 0.3.0 anchor sizes — `principles.md` at 66 lines
# is the lower end; `RUNTIME.md` at 462 is the upper end before it should split.
MAX_LINES = 500
MIN_LINES = 30


def _load_backbone() -> dict | None:
    if not BACKBONE.exists():
        return None
    try:
        data = yaml.safe_load(BACKBONE.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        print(f"specs-check: backbone config failed to parse: {exc}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(data, dict):
        print("specs-check: backbone config did not parse to a mapping", file=sys.stderr)
        sys.exit(2)
    return data


def _subsystems(backbone: dict) -> dict[str, dict]:
    subs = backbone.get("subsystems") or {}
    if not isinstance(subs, dict):
        return {}
    return {k: v for k, v in subs.items() if isinstance(v, dict)}


def check_coverage(subs: dict[str, dict]) -> list[str]:
    fails: list[str] = []
    for name, entry in subs.items():
        spec = entry.get("spec")
        if not spec:
            fails.append(f"{name}: missing `spec` field")
            continue
        if not (ROOT / spec).exists():
            fails.append(f"{name}: spec not found at {spec}")
    return fails


def check_shape(subs: dict[str, dict]) -> list[str]:
    fails: list[str] = []
    for name, entry in subs.items():
        spec = entry.get("spec")
        if not spec:
            continue
        p = ROOT / spec
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8")
        lines = text.count("\n") + 1
        if lines > MAX_LINES:
            fails.append(f"{name}: {spec} is {lines} lines (cap {MAX_LINES}) — split into subordinate specs")
        elif lines < MIN_LINES:
            fails.append(f"{name}: {spec} is {lines} lines (min {MIN_LINES}) — too thin, expand or fold into a parent spec")
        if not text.lstrip().startswith("# "):
            fails.append(f"{name}: {spec} missing H1 title")
    return fails


def check_colocation(subs: dict[str, dict]) -> list[str]:
    """Modules per subsystem should cluster under one parent directory.

    When a subsystem lists modules in 2+ distinct parent directories, the
    subsystem boundary is sharper in the doc than in the code. Flag for
    consolidation — typically the fix is to create a named subpackage
    (e.g., `core/cache/` containing `cache.py`, `check_cache.py`, `map_cache.py`)
    that matches the subsystem.
    """
    fails: list[str] = []
    for name, entry in subs.items():
        mods = entry.get("modules") or []
        if not mods or len(mods) < 2:
            continue
        parents = {str(Path(m).parent) for m in mods if isinstance(m, str)}
        if len(parents) <= 1:
            continue
        parent_list = ", ".join(sorted(parents))
        fails.append(
            f"{name}: modules span {len(parents)} parent dirs ({parent_list}) — "
            f"consider consolidating under a single subpackage matching the subsystem"
        )
    return fails


def check_orphans(subs: dict[str, dict]) -> list[str]:
    """Spec files that exist on disk but are not declared in `subsystems:`."""
    declared = [entry["spec"] for entry in subs.values() if entry.get("spec")]
    if not declared:
        return []
    spec_root = ROOT / commonpath(declared)
    if not spec_root.is_dir():
        return []
    declared_set = {str((ROOT / s).resolve()) for s in declared}
    orphans: list[str] = []
    for p in sorted(spec_root.rglob("*.md")):
        if p.name == "CLAUDE.md":
            continue
        if str(p.resolve()) not in declared_set:
            orphans.append(str(p.relative_to(ROOT)))
    return orphans


def main() -> int:
    backbone = _load_backbone()
    if backbone is None:
        print("specs-check: no backbone config; skipped")
        return 0
    subs = _subsystems(backbone)
    if not subs:
        print("specs-check: no `subsystems:` section in backbone config; nothing to check")
        return 0

    cov = check_coverage(subs)
    shape = check_shape(subs)
    coloc = check_colocation(subs)
    orphans = check_orphans(subs)

    issues = 0
    if cov:
        print("COVERAGE FAILURES:")
        for f in cov:
            print(f"  - {f}")
        issues += len(cov)
    if shape:
        print("SHAPE FAILURES:")
        for f in shape:
            print(f"  - {f}")
        issues += len(shape)
    if coloc:
        print("CO-LOCATION WARNINGS:")
        for f in coloc:
            print(f"  - {f}")
        issues += len(coloc)
    if orphans:
        print("ORPHAN SPECS (exist on disk but not declared in `subsystems:`):")
        for o in orphans:
            print(f"  - {o}")
        issues += len(orphans)

    if issues == 0:
        print(f"specs-check: {len(subs)} subsystems, all covered, within shape contract, co-located.")
        return 0
    print(f"specs-check: {issues} issue(s) across {len(subs)} subsystems")
    return 1


if __name__ == "__main__":
    sys.exit(main())
