"""Subsystems stay inside core — `core/<subsystem>/` imports nothing from `interfaces/` or `formatters/`.

`interfaces/` and `formatters/` compose the subsystems; a subsystem that reached back out to
either would put the dependency arrow the wrong way round.

No core module outside `core/platform/adapters/` imports a driven adapter: core declares the port
it needs and the entry point passes the adapter in.
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

_ADAPTERS = "reporails_cli.core.platform.adapters"


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
        f"{py.relative_to(ROOT).as_posix()} imports {imp}"
        for subsystem in subsystems
        for py in sorted(subsystem.rglob("*.py"))
        if "__pycache__" not in py.parts
        for imp in _iter_imports(py)
        if imp.startswith(_FORBIDDEN_PREFIXES)
    ]
    assert not violations, "a core subsystem imports an outer layer:\n  " + "\n  ".join(violations)


def _is_adapter(target: str) -> bool:
    return target == _ADAPTERS or target.startswith(_ADAPTERS + ".")


def _absolute_targets(module: str, is_package: bool, node: ast.ImportFrom) -> list[str]:
    """Every dotted module an `ImportFrom` can bind, relative imports resolved against `module`."""
    if node.level:
        base = module.split(".") if is_package else module.split(".")[:-1]
        base = base[: len(base) - (node.level - 1)]
        package = ".".join(base + ([node.module] if node.module else []))
    else:
        package = node.module or ""
    return [package, *(f"{package}.{alias.name}" for alias in node.names)]


def _adapter_imports(core: Path) -> list[str]:
    """`<file>:<line> imports <module>` for each import of a driven adapter outside `core/platform/adapters/`.

    Reads every import form: absolute, relative, inside a function, under `TYPE_CHECKING`, and the
    package itself (`from reporails_cli.core.platform import adapters`).
    """
    src = core.parent.parent
    adapters_dir = core / "platform" / "adapters"
    found: list[str] = []
    for py in sorted(core.rglob("*.py")):
        if "__pycache__" in py.parts or py.is_relative_to(adapters_dir):
            continue
        parts = list(py.relative_to(src).with_suffix("").parts)
        is_package = parts[-1] == "__init__"
        module = ".".join(parts[:-1] if is_package else parts)
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                targets = _absolute_targets(module, is_package, node)
            else:
                continue
            # One finding per statement: `from adapters.x import y` names both `adapters.x` and `adapters.x.y`.
            hit = next((target for target in targets if _is_adapter(target)), None)
            if hit:
                found.append(f"{py.relative_to(src).as_posix()}:{node.lineno} imports {hit}")
    return found


@pytest.mark.architecture
def test_core_imports_no_driven_adapter() -> None:
    """No module under `core/`, outside `core/platform/adapters/`, imports a driven adapter."""
    assert CORE.is_dir(), f"{CORE} must exist"
    found = _adapter_imports(CORE)
    assert not found, "core imports a driven adapter:\n  " + "\n  ".join(found)


def _plant(tmp_path: Path, rel: str, text: str) -> Path:
    core = tmp_path / "reporails_cli" / "core"
    path = core / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return core


@pytest.mark.architecture
@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("lint/absolute.py", "from reporails_cli.core.platform.adapters.registry import load_rules\n"),
        ("lint/plain.py", "import reporails_cli.core.platform.adapters.registry\n"),
        ("lint/package.py", "from reporails_cli.core.platform import adapters\n"),
        ("platform/runtime/relative.py", "from ..adapters.rules_query import rule_title\n"),
        ("platform/runtime/relative_package.py", "from .. import adapters\n"),
        ("platform/runtime/__init__.py", "from ..adapters import payload\n"),
        (
            "lint/lazy.py",
            "def f():\n    from reporails_cli.core.platform.adapters import payload\n    return payload\n",
        ),
        (
            "lint/typing_only.py",
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from reporails_cli.core.platform.adapters.api_client import AilsClient\n",
        ),
    ],
)
def test_every_import_form_of_an_adapter_is_caught(tmp_path: Path, rel: str, text: str) -> None:
    found = _adapter_imports(_plant(tmp_path, rel, text))
    assert len(found) == 1, found
    assert found[0].startswith(f"reporails_cli/core/{rel}:")


@pytest.mark.architecture
@pytest.mark.parametrize(
    ("rel", "text"),
    [
        (
            "platform/adapters/api_client.py",
            "from reporails_cli.core.platform.adapters.payload import encode_msgpack\n",
        ),
        ("eventbus/dispatcher.py", "from reporails_cli.core.eventbus.adapters.claude import ClaudeAdapter\n"),
        ("eventbus/transcript.py", "from .adapters.claude_transcript import ClaudeTranscriptAdapter\n"),
        ("platform/runtime/merger.py", "from reporails_cli.core.platform.rules.rules_query import rule_title\n"),
    ],
)
def test_adapters_and_non_adapter_packages_stay_quiet(tmp_path: Path, rel: str, text: str) -> None:
    assert _adapter_imports(_plant(tmp_path, rel, text)) == []
