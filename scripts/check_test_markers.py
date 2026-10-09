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
# Lanes whose tests are cross-cutting by definition and therefore exempt from
# the "at least one subsys_* marker" requirement.
SUBSYS_EXEMPT_LANES = {"architecture", "contract"}

# Owners that run the real mapper. A unit test that runs the mapper must carry `requires_model`,
# so a runner without the model set skips it.
MAPPER_ENTRIES = {"map_instruction_files", "map_ruleset", "apply_keyed_heal"}
INTERFACES = ROOT / "src" / "reporails_cli" / "interfaces"
MODEL_MARKER = "requires_model"
MAPPER_MODULES = (".core.mapper.", ".core.pipeline.")
MAPPER_ALIASES = {"pl", "mapping", "pipeline"}

# Audit mode: when False, the script reports without failing.
FAIL_ON_MISSING = True


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


def _markers_on(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> set[str]:
    """Return the set of `pytest.mark.<name>` decorators on a function or class node."""
    out: set[str] = set()
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if not isinstance(target, ast.Attribute):
            continue
        value = target.value
        is_pytest_mark = (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id == "pytest"
            and value.attr == "mark"
        )
        is_mark = isinstance(value, ast.Name) and value.id == "mark"
        if is_pytest_mark or is_mark:
            out.add(target.attr)
    return out


def _called_names(node: ast.AST, *, bare_only: bool = False) -> set[str]:
    """Names of the functions called anywhere inside `node`: `f(...)`, and `mod.f(...)` unless `bare_only`."""
    out: set[str] = set()
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        if isinstance(func, ast.Name):
            out.add(func.id)
        elif isinstance(func, ast.Attribute) and not bare_only:
            out.add(func.attr)
    return out


def _stubs_mapper(node: ast.AST) -> bool:
    """Whether a test replaces a part of the mapper or its pipeline (`monkeypatch.setattr` / `patch`).

    A target is the dotted string (`"reporails_cli.core.mapper.daemon.start_daemon"`) or the
    module the test imported the pipeline as (`pl`, `mapping`)."""
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
        if name not in {"setattr", "patch"} or not sub.args:
            continue
        target = sub.args[0]
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            if any(part in target.value for part in MAPPER_MODULES):
                return True
        elif isinstance(target, ast.Name) and target.id in MAPPER_ALIASES:
            return True
    return False


def _pytestmark_names(body: list[ast.stmt]) -> set[str]:
    """Marker names set by a `pytestmark = [...]` assignment in a module or class body."""
    out: set[str] = set()
    for stmt in body:
        if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in stmt.targets):
            out.update(n.attr for n in ast.walk(stmt.value) if isinstance(n, ast.Attribute))
    return out


def _functions(body: list[ast.stmt]) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [n for n in body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _reaching(body: list[ast.stmt], entries: set[str]) -> set[str]:
    """Function names in `body` that reach an entry, directly or through each other.

    Entries match by name, called bare or as `mod.f(...)`; other functions of the body are
    followed only through bare-name calls, so `obj._run(...)` never matches a helper `_run`."""
    funcs = _functions(body)
    reaching = {f.name for f in funcs if _called_names(f) & entries}
    grew = True
    while grew:
        grew = False
        for f in funcs:
            if f.name not in reaching and _called_names(f, bare_only=True) & reaching:
                reaching.add(f.name)
                grew = True
    return reaching


def _src_entries() -> set[str]:
    """The mapper owners plus the interface functions that call one directly, so a test that goes through
    an interface wrapper is covered."""
    entries = set(MAPPER_ENTRIES)
    for path in sorted(INTERFACES.rglob("*.py")):
        try:
            body = ast.parse(path.read_text(encoding="utf-8")).body
        except (SyntaxError, UnicodeDecodeError):
            continue
        entries |= {f.name for f in _functions(body) if _called_names(f, bare_only=True) & MAPPER_ENTRIES}
    return entries


def _tests(body: list[ast.stmt], inherited: set[str]) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, set[str]]]:
    """Test functions of a module or class body with the markers their enclosing classes set."""
    out = [(f, inherited) for f in _functions(body) if f.name.startswith("test_")]
    for cls in (n for n in body if isinstance(n, ast.ClassDef)):
        out.extend(_tests(cls.body, inherited | _markers_on(cls) | _pytestmark_names(cls.body)))
    return out


def _audit_file(path: Path, allowed_subsys: set[str], entries: set[str]) -> list[tuple[str, str]]:
    """Return list of `(function_label, reason)` for tagging gaps."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError) as exc:
        return [(str(path), f"could not parse: {exc}")]

    gaps: list[tuple[str, str]] = []
    in_unit = "unit" in path.relative_to(TESTS).parts[:1]
    helpers = _reaching(tree.body, entries)
    module_markers = _pytestmark_names(tree.body)
    for node, inherited in _tests(tree.body, set()):
        markers = _markers_on(node)
        reaches = _called_names(node) & entries or _called_names(node, bare_only=True) & helpers
        if in_unit and reaches and not _stubs_mapper(node) and MODEL_MARKER not in markers | inherited | module_markers:
            gaps.append((f"{path.relative_to(ROOT)}::{node.name}", "runs the mapper without requires_model"))
        label = f"{path.relative_to(ROOT)}::{node.name}"
        markers = markers | inherited
        lanes = markers & LANE_MARKERS
        subsys = {m for m in markers if m.startswith(SUBSYS_PREFIX)}
        if not lanes:
            gaps.append((label, "no lane marker"))
        elif len(lanes) > 1:
            gaps.append((label, f"multiple lane markers: {sorted(lanes)}"))
        if not subsys and not (lanes & SUBSYS_EXEMPT_LANES):
            gaps.append((label, "no subsys_* marker"))
        unknown = subsys - allowed_subsys
        if unknown:
            gaps.append((label, f"unknown subsystem marker(s): {sorted(unknown)}"))
    return gaps


def _count_tests(path: Path) -> int:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return 0
    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
    )


def _walk_test_files() -> list[Path]:
    return [p for p in sorted(TESTS.rglob("test_*.py")) if "__pycache__" not in p.parts]


def _print_summary(gaps: list[tuple[str, str]], total_tests: int, files_audited: int) -> None:
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


def main() -> int:
    if not TESTS.is_dir():
        print(f"check_test_markers: {TESTS} missing")
        return 0
    allowed_subsys = _load_subsys_markers()
    if not allowed_subsys:
        print("check_test_markers: no subsys_* markers registered in pyproject.toml")
        return 0

    test_files = _walk_test_files()
    gaps: list[tuple[str, str]] = []
    total_tests = 0
    entries = _src_entries()
    for path in test_files:
        gaps.extend(_audit_file(path, allowed_subsys, entries))
        total_tests += _count_tests(path)

    if not gaps:
        print(f"check_test_markers: {total_tests} test(s) across {len(test_files)} file(s); all tagged correctly")
        return 0

    _print_summary(gaps, total_tests, len(test_files))

    if FAIL_ON_MISSING:
        return 1
    print("\n(report-only mode; flip FAIL_ON_MISSING in this file to enforce)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
