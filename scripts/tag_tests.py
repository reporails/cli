#!/usr/bin/env python3
"""One-shot auto-tagger: add lane + subsystem markers to every `test_*` function.

Walks `tests/`, parses each file with `ast`, and inserts `@pytest.mark.<lane>` and
`@pytest.mark.<subsys_*>` decorators above each test function that lacks them.
The script is **idempotent** — re-running skips already-tagged functions.

Lane is derived from the directory (`tests/unit/` → `unit`, etc.) with explicit
overrides for files that belong to a different lane than their location suggests.
Subsystem(s) are looked up per file in `_MAPPING` below.

Run: `uv run python scripts/tag_tests.py`
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

LANE_BY_DIR = {
    "tests/unit": "unit",
    "tests/integration": "integration",
    "tests/smoke": "e2e",
}

LANE_MARKERS = {"unit", "integration", "e2e", "smoke", "architecture", "contract"}
SUBSYS_PREFIX = "subsys_"

# Explicit per-file mapping. First element overrides the directory-derived lane
# (None = keep directory default). Second element is the list of subsys_* tags.
_MAPPING: dict[str, tuple[str | None, list[str]]] = {
    # tests/integration/
    "tests/integration/test_behavioral.py": (None, ["subsys_lint", "subsys_diagnostic"]),
    "tests/integration/test_capability_detection.py": (None, ["subsys_cli_ux"]),
    "tests/integration/test_cli_e2e.py": ("e2e", ["subsys_cli_ux"]),
    "tests/integration/test_mcp_e2e.py": ("e2e", ["subsys_cli_ux", "subsys_api"]),
    "tests/integration/test_self_update.py": (None, ["subsys_cli_ux"]),
    "tests/integration/test_symlink_validation.py": (None, ["subsys_lint"]),
    "tests/integration/test_template_resolution.py": (None, ["subsys_lint"]),
    # tests/smoke/
    "tests/smoke/test_smoke.py": ("e2e", ["subsys_cli_ux"]),
    # tests/unit/
    "tests/unit/test_agent_config.py": (None, ["subsys_lint"]),
    "tests/unit/test_agents_dedupe.py": (None, ["subsys_lint"]),
    "tests/unit/test_api_client.py": (None, ["subsys_api"]),
    "tests/unit/test_applicability.py": (None, ["subsys_lint"]),
    "tests/unit/test_backbone_gate.py": (None, ["subsys_map", "subsys_cli_ux"]),
    "tests/unit/test_byte_preflight.py": (None, ["subsys_cli_ux"]),
    "tests/unit/test_cache.py": (None, ["subsys_caching"]),
    "tests/unit/test_cache_structural.py": (None, ["subsys_caching"]),
    "tests/unit/test_check_cache.py": (None, ["subsys_caching"]),
    "tests/unit/test_classification.py": (None, ["subsys_classify"]),
    "tests/unit/test_client_checks.py": (None, ["subsys_lint"]),
    "tests/unit/test_config_command.py": (None, ["subsys_cli_ux"]),
    "tests/unit/test_discover.py": (None, ["subsys_lint"]),
    "tests/unit/test_download_rules_staging.py": (None, ["subsys_cli_ux"]),
    "tests/unit/test_engine_helpers.py": (None, ["subsys_lint", "subsys_runtime"]),
    "tests/unit/test_exit_codes.py": (None, ["subsys_cli_ux"]),
    "tests/unit/test_funnel.py": (None, ["subsys_funnel"]),
    "tests/unit/test_gates.py": (None, ["subsys_gates"]),
    "tests/unit/test_github_formatter.py": (None, ["subsys_diagnostic"]),
    "tests/unit/test_harness.py": (None, ["subsys_lint"]),
    "tests/unit/test_json_formatter.py": (None, ["subsys_diagnostic"]),
    "tests/unit/test_mcp_install.py": (None, ["subsys_cli_ux"]),
    "tests/unit/test_mechanical.py": (None, ["subsys_lint"]),
    "tests/unit/test_merger.py": (None, ["subsys_lint"]),
    "tests/unit/test_package_levels.py": (None, ["subsys_gates"]),
    "tests/unit/test_payload.py": (None, ["subsys_server"]),
    "tests/unit/test_project_config.py": (None, ["subsys_cli_ux"]),
    "tests/unit/test_recommended.py": (None, ["subsys_lint"]),
    "tests/unit/test_regex_engine.py": (None, ["subsys_lint"]),
    "tests/unit/test_registry.py": (None, ["subsys_lint"]),
    "tests/unit/test_rule_runner.py": (None, ["subsys_lint"]),
    "tests/unit/test_rule_validation.py": (None, ["subsys_lint"]),
    "tests/unit/test_safe_extract.py": (None, ["subsys_cli_ux"]),
    "tests/unit/test_scan_scope.py": (None, ["subsys_lint"]),
    "tests/unit/test_scorecard.py": (None, ["subsys_diagnostic"]),
    "tests/unit/test_self_update.py": (None, ["subsys_cli_ux"]),
    "tests/unit/test_stopwords.py": (None, ["subsys_map"]),
    "tests/unit/test_summary.py": (None, ["subsys_diagnostic"]),
    "tests/unit/test_symlink_detection.py": (None, ["subsys_lint"]),
    "tests/unit/test_update_check.py": (None, ["subsys_cli_ux"]),
}


def _determine_lane(rel_path: str) -> str | None:
    for dir_prefix, lane in LANE_BY_DIR.items():
        if rel_path.startswith(dir_prefix + "/"):
            return lane
    return None


def _existing_markers(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    out: set[str] = set()
    for dec in node.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute):
            value = target.value
            if (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id == "pytest"
                and value.attr == "mark"
            ):
                out.add(target.attr)
    return out


def _file_has_pytest_import(tree: ast.Module) -> bool:
    for node in tree.body:
        if isinstance(node, ast.Import) and any(a.name == "pytest" for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module == "pytest":
            return True
    return False


def _tag_file(path: Path) -> tuple[int, int]:
    rel = str(path.relative_to(ROOT))
    lane = _determine_lane(rel)
    override_lane, subsystems = _MAPPING.get(rel, (None, []))
    if override_lane:
        lane = override_lane
    if not lane or not subsystems:
        return (0, 0)

    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        print(f"{rel}: skipped — could not parse: {exc}", file=sys.stderr)
        return (0, 0)

    tagged = skipped = 0
    insertions: list[tuple[int, list[str]]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("test_"):
            continue
        existing = _existing_markers(node)
        has_lane = bool(existing & LANE_MARKERS)
        has_subsys = any(m.startswith(SUBSYS_PREFIX) for m in existing)
        if has_lane and has_subsys:
            skipped += 1
            continue
        indent = " " * node.col_offset
        if node.decorator_list:
            insert_at = node.decorator_list[0].lineno - 1
        else:
            insert_at = node.lineno - 1
        new_decorators: list[str] = []
        if not has_lane:
            new_decorators.append(f"{indent}@pytest.mark.{lane}")
        if not has_subsys:
            new_decorators.extend(f"{indent}@pytest.mark.{m}" for m in subsystems)
        insertions.append((insert_at, new_decorators))
        tagged += 1

    if not insertions:
        return (0, skipped)

    needs_pytest_import = not _file_has_pytest_import(tree)
    for insert_at, new_decorators in sorted(insertions, key=lambda t: -t[0]):
        lines[insert_at:insert_at] = new_decorators

    if needs_pytest_import:
        # Only consider top-level imports (col_offset == 0); local imports inside
        # functions or classes must not be treated as the insertion anchor.
        last_top_import_line = 0
        for top in tree.body:
            if isinstance(top, (ast.Import, ast.ImportFrom)):
                last_top_import_line = top.end_lineno or top.lineno
        # Inserting at end_lineno places `import pytest` on the line after the
        # last top-level import. The other inserts above already happened in
        # reverse order, so this index still points correctly.
        lines.insert(last_top_import_line, "import pytest")

    path.write_text("\n".join(lines), encoding="utf-8")
    return (tagged, skipped)


def main() -> int:
    total_tagged = total_skipped = 0
    files_processed = 0
    for path in sorted(TESTS.rglob("test_*.py")):
        if "__pycache__" in path.parts:
            continue
        tagged, skipped = _tag_file(path)
        files_processed += 1
        if tagged or skipped:
            print(f"{path.relative_to(ROOT)}: tagged {tagged}, already-tagged {skipped}")
        total_tagged += tagged
        total_skipped += skipped

    unmapped = []
    for path in sorted(TESTS.rglob("test_*.py")):
        rel = str(path.relative_to(ROOT))
        if "__pycache__" in path.parts:
            continue
        if rel not in _MAPPING:
            unmapped.append(rel)
    if unmapped:
        print(f"\n{len(unmapped)} file(s) without a subsystem mapping (left untagged):")
        for u in unmapped:
            print(f"  - {u}")

    print(f"\nTotal: {total_tagged} tagged, {total_skipped} already tagged, {files_processed} files processed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
