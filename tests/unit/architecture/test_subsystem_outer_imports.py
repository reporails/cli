"""Subsystems stay inside core — `core/<subsystem>/` imports nothing from `interfaces/` or `formatters/`.

`interfaces/` and `formatters/` compose the subsystems; a subsystem that reached back out to
either would put the dependency arrow the wrong way round.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent.parent
CORE = ROOT / "src" / "reporails_cli" / "core"

_FORBIDDEN_PREFIXES = (
    "reporails_cli.interfaces",
    "reporails_cli.formatters",
)


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
def test_subsystems_do_not_import_interfaces_or_formatters() -> None:
    """No module under `core/<subsystem>/` imports from `interfaces/` or `formatters/`."""
    assert CORE.is_dir(), f"{CORE} must exist"
    subsystems = sorted(p for p in CORE.iterdir() if p.is_dir() and p.name not in {"platform", "__pycache__"})
    assert subsystems, "core/ must hold subsystems"
    violations = [
        f"{py.relative_to(ROOT)} imports {imp}"
        for subsystem in subsystems
        for py in sorted(subsystem.rglob("*.py"))
        if "__pycache__" not in py.parts
        for imp in _iter_imports(py)
        if imp.startswith(_FORBIDDEN_PREFIXES)
    ]
    assert not violations, "a core subsystem imports an outer layer:\n  " + "\n  ".join(violations)
