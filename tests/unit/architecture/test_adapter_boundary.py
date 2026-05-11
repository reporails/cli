"""Adapter boundary — `core/platform/adapters/` consumes core, not subsystems.

`adapters/` translates between the pure core layer and wired state. It may
import from `core/platform/{contract,dto,policy}` and from
`core/platform/{config,observability,utils}` (infrastructure). It must NOT
import from any `core/<subsystem>/` (cache, classify, mapper, ...) or from
`interfaces/` or `formatters/`. Subsystems import adapters, not the reverse.

Runs in **report-only** mode today. Flip `_FAIL_ON_VIOLATION = True` once
Phase 5 of the platform migration completes.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent.parent
ADAPTERS = ROOT / "src" / "reporails_cli" / "core" / "platform" / "adapters"

_FORBIDDEN_PREFIXES = (
    "reporails_cli.interfaces",
    "reporails_cli.formatters",
)

_FORBIDDEN_SUBSYSTEM_PREFIXES = (
    "reporails_cli.core.cache.",
    "reporails_cli.core.classify.",
    "reporails_cli.core.discovery.",
    "reporails_cli.core.funnel.",
    "reporails_cli.core.heal.",
    "reporails_cli.core.install.",
    "reporails_cli.core.lint.",
    "reporails_cli.core.mapper.",
)

_FAIL_ON_VIOLATION = True

# Known temporary exceptions. Each entry: (importer_path_relative_to_root, imported_module).
# Removed as the corresponding migration phase completes.
_KNOWN_EXCEPTIONS: set[tuple[str, str]] = set()  # all entries resolved by Phase 7


def _iter_imports(file_path: Path) -> list[str]:
    try:
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return []
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.append(node.module)
    return out


@pytest.mark.architecture
def test_adapters_do_not_import_subsystems_or_outer_layers() -> None:
    """Adapters must not depend on subsystems, interfaces, or formatters."""
    if not ADAPTERS.is_dir():
        pytest.skip(f"{ADAPTERS} does not exist yet")
    forbidden = _FORBIDDEN_PREFIXES + _FORBIDDEN_SUBSYSTEM_PREFIXES
    violations: list[tuple[Path, str]] = [
        (py, imp)
        for py in sorted(ADAPTERS.rglob("*.py"))
        if "__pycache__" not in py.parts
        for imp in _iter_imports(py)
        if any(imp.startswith(prefix) for prefix in forbidden)
        and (str(py.relative_to(ROOT)), imp) not in _KNOWN_EXCEPTIONS
    ]
    if not violations:
        return
    lines = [f"adapters layer has {len(violations)} forbidden import(s):"]
    lines.extend(f"  {v[0].relative_to(ROOT)} imports {v[1]}" for v in violations)
    msg = "\n".join(lines)
    if _FAIL_ON_VIOLATION:
        pytest.fail(msg)
    else:
        print(f"\n[report-only]\n{msg}\n")
