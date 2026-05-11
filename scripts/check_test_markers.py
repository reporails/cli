#!/usr/bin/env python3
"""Audit `tests/` for the marker taxonomy declared in `pyproject.toml`.

Every test function should declare:

- exactly one **lane** marker (`unit`, `integration`, `e2e`, `smoke`, `architecture`, `contract`)
- at least one **subsystem** marker (`subsys_*`)

This audit currently runs in **report-only** mode — it prints findings without
exiting non-zero. Once existing tests are bulk-tagged, the script will be
flipped to fail mode (set `FAIL_ON_MISSING = True`) and wired into `qa_fast`.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
PYPROJECT = ROOT / "pyproject.toml"

LANE_MARKERS = {"unit", "integration", "e2e", "smoke", "architecture", "contract"}
SUBSYS_PREFIX = "subsys_"

# Audit mode: when False, the script reports without failing.
FAIL_ON_MISSING = False


def _load_subsys_markers() -> set[str]:
    """Read the registered `subsys_*` marker names from `pyproject.toml`."""
    if not PYPROJECT.exists():
        return set()
    with PYPROJECT.open("rb") as fh:
        data = tomllib.load(fh)
    raw = data.get("tool", {}).get("pytest", {}).get("ini_options", {}).get("markers", [])
    out: set[str] = set()
    for entry in raw:
        if not isinstance(entry, str):
            continue
        name = entry.split(":", 1)[0].strip()
        if name.startswith(SUBSYS_PREFIX):
            out.add(name)
    return out


def _markers_on(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return the set of `pytest.mark.<name>` decorators on a function node."""
    out: set[str] = set()
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        # match `pytest.mark.<name>` and `mark.<name>`
        if isinstance(target, ast.Attribute):
            if (
                isinstance(target.value, ast.Attribute)
                and isinstance(target.value.value, ast.Name)
                and target.value.value.id == "pytest"
                and target.value.attr == "mark"
            ):
                out.add(target.attr)
            elif isinstance(target.value, ast.Name) and target.value.id == "mark":
                out.add(target.attr)
    return out


def _audit_file(path: Path, allowed_subsys: set[str]) -> list[tuple[str, str]]:
    """Return list of `(function_label, reason)` for tagging gaps."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError) as exc:
        return [(str(path), f"could not parse: {exc}")]

    gaps: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("test_"):
            continue
        markers = _markers_on(node)
        label = f"{path.relative_to(ROOT)}::{node.name}"
        lanes = markers & LANE_MARKERS
        subsys = {m for m in markers if m.startswith(SUBSYS_PREFIX)}
        if not lanes:
            gaps.append((label, "no lane marker"))
        elif len(lanes) > 1:
            gaps.append((label, f"multiple lane markers: {sorted(lanes)}"))
        if not subsys:
            gaps.append((label, "no subsys_* marker"))
        unknown = subsys - allowed_subsys
        if unknown:
            gaps.append((label, f"unknown subsystem marker(s): {sorted(unknown)}"))
    return gaps


def main() -> int:
    if not TESTS.is_dir():
        print(f"check_test_markers: {TESTS} missing")
        return 0
    allowed_subsys = _load_subsys_markers()
    if not allowed_subsys:
        print("check_test_markers: no subsys_* markers registered in pyproject.toml")
        return 0

    total_tests = 0
    files_audited = 0
    gaps: list[tuple[str, str]] = []
    for path in sorted(TESTS.rglob("test_*.py")):
        if "__pycache__" in path.parts:
            continue
        files_audited += 1
        file_gaps = _audit_file(path, allowed_subsys)
        gaps.extend(file_gaps)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        total_tests += sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
        )

    if not gaps:
        print(f"check_test_markers: {total_tests} test(s) across {files_audited} file(s); all tagged correctly")
        return 0

    by_reason: dict[str, int] = {}
    for _, reason in gaps:
        bucket = reason.split(":")[0]
        by_reason[bucket] = by_reason.get(bucket, 0) + 1

    print(f"check_test_markers: {len(gaps)} gap(s) across {total_tests} test(s) in {files_audited} file(s)")
    print("\nBy reason:")
    for reason, count in sorted(by_reason.items(), key=lambda t: -t[1]):
        print(f"  {count:4d}  {reason}")

    if "-v" in sys.argv or "--verbose" in sys.argv:
        print("\nDetails:")
        for label, reason in gaps[:50]:
            print(f"  - {label}: {reason}")
        if len(gaps) > 50:
            print(f"  ... and {len(gaps) - 50} more")

    if FAIL_ON_MISSING:
        return 1
    print("\n(report-only mode; not failing — flip FAIL_ON_MISSING in this file to enforce)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
