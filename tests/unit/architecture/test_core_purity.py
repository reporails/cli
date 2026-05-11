"""Hexagonal core purity — `core/platform/{contract,dto,policy}` must be pure.

Pure means: no imports from `core/platform/{adapters,runtime,config,observability,utils}`,
no imports from any `core/<subsystem>/` package, no imports from `interfaces/` or
`formatters/`. Validators, data shapes, and decision functions in the pure core
layer should be testable in isolation without dragging wiring or framework code.

Runs in **report-only** mode today — prints violations without failing — because
the platform substrate is freshly bootstrapped and code has not yet migrated
into `contract/`, `dto/`, `policy/`. The check is wired up so it catches the
first regression once migration begins.

Flip `_FAIL_ON_VIOLATION = True` once Phase 5 of the platform migration completes.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent.parent
PLATFORM = ROOT / "src" / "reporails_cli" / "core" / "platform"
PURE_LAYERS = ("contract", "dto", "policy")

# Imports that pure layers must not pull in.
_FORBIDDEN_PREFIXES = (
    "reporails_cli.core.platform.adapters",
    "reporails_cli.core.platform.runtime",
    "reporails_cli.core.platform.config",
    "reporails_cli.core.platform.observability",
    "reporails_cli.core.platform.utils",
    "reporails_cli.interfaces",
    "reporails_cli.formatters",
)

# Subsystem subpackages (siblings of `platform/` inside `core/`). Populated as
# subsystems migrate. Pure layers must not depend on them.
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
_KNOWN_EXCEPTIONS: set[tuple[str, str]] = set()


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


def _forbidden_imports_in(layer_dir: Path) -> list[tuple[Path, str]]:
    if not layer_dir.is_dir():
        return []
    forbidden = _FORBIDDEN_PREFIXES + _FORBIDDEN_SUBSYSTEM_PREFIXES
    return [
        (py, imp)
        for py in sorted(layer_dir.rglob("*.py"))
        if "__pycache__" not in py.parts
        for imp in _iter_imports(py)
        if any(imp.startswith(prefix) for prefix in forbidden)
        and (str(py.relative_to(ROOT)), imp) not in _KNOWN_EXCEPTIONS
    ]


@pytest.mark.architecture
def test_platform_skeleton_exists() -> None:
    """Sanity check: the eight platform layer directories exist."""
    expected = {"contract", "dto", "policy", "adapters", "runtime", "config", "observability", "utils"}
    actual = {p.name for p in PLATFORM.iterdir() if p.is_dir() and not p.name.startswith("_")}
    missing = expected - actual
    assert not missing, f"platform layer directories missing: {sorted(missing)}"


@pytest.mark.architecture
def test_pure_layers_have_no_forbidden_imports() -> None:
    """`core/platform/{contract,dto,policy}` must not import wiring or subsystem code."""
    all_violations: list[tuple[Path, str]] = []
    for layer in PURE_LAYERS:
        all_violations.extend(_forbidden_imports_in(PLATFORM / layer))
    if not all_violations:
        return
    lines = [f"pure core has {len(all_violations)} forbidden import(s):"]
    lines.extend(f"  {v[0].relative_to(ROOT)} imports {v[1]}" for v in all_violations)
    msg = "\n".join(lines)
    if _FAIL_ON_VIOLATION:
        pytest.fail(msg)
    else:
        print(f"\n[report-only]\n{msg}\n")
