"""Programs run only through `interfaces/cli/helpers.py`.

One rule, pure `ast`, over every `src/reporails_cli/**/*.py`:

- P1 stray process: `import subprocess`, `import subprocess as x` or `from subprocess import ...` in
  any module but `interfaces/cli/helpers.py`; and, anywhere in src, a call to `os.system`,
  `os.popen`, `os.startfile`, `os.spawn*`, `os.exec*` or `os.posix_spawn*` (through `import os`,
  an alias of it, or a name imported from `os`). `os.fork` is allowed: the mapper daemon owns its
  own start.

Why: a program started in many places gets its timeout, error handling and environment many ways.
One runner gives every start the same answer to "it cannot start" and "it ran out of time".

The scanner takes the source files and their root, so the planted tests below run the same code on
tmp files.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = pytest.mark.architecture

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SRC = ROOT / "src" / "reporails_cli"
RUNNER = "interfaces/cli/helpers.py"

_OS_EXACT = {"system", "popen", "startfile"}
_OS_PREFIXES = ("spawn", "exec", "posix_spawn")


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule and a human line."""

    rule: str
    detail: str


def _starts_a_program(name: str) -> bool:
    return name in _OS_EXACT or name.startswith(_OS_PREFIXES)


def _os_names(tree: ast.Module) -> set[str]:
    """The local names the `os` module is bound to: `import os`, `import os as x`, `import os.path`."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import):
            continue
        for alias in node.names:
            if alias.name == "os":
                names.add(alias.asname or "os")
            elif alias.name.startswith("os.") and not alias.asname:
                names.add("os")
    return names


def _is_subprocess(module: str | None) -> bool:
    return module == "subprocess" or (module or "").startswith("subprocess.")


def stray_process_violations(sources: list[Path], root: Path) -> list[Violation]:
    """P1: a program started outside the one runner."""
    out: list[Violation] = []
    for py in sources:
        rel = py.relative_to(root).as_posix()
        tree = ast.parse(py.read_text(encoding="utf-8"))
        modules = _os_names(tree)
        from_os = {
            alias.asname or alias.name: alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module == "os"
            for alias in node.names
            if _starts_a_program(alias.name)
        }
        for node in ast.walk(tree):
            if rel != RUNNER and isinstance(node, ast.Import):
                out.extend(
                    Violation("P1", f"{rel}:{node.lineno} imports {alias.name}")
                    for alias in node.names
                    if _is_subprocess(alias.name)
                )
            elif rel != RUNNER and isinstance(node, ast.ImportFrom) and _is_subprocess(node.module):
                out.append(Violation("P1", f"{rel}:{node.lineno} imports from {node.module}"))
            elif isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id in modules
                    and _starts_a_program(func.attr)
                ):
                    out.append(Violation("P1", f"{rel}:{node.lineno} calls os.{func.attr}"))
                elif isinstance(func, ast.Name) and func.id in from_os:
                    out.append(Violation("P1", f"{rel}:{node.lineno} calls os.{from_os[func.id]}"))
    return out


def _src_files() -> list[Path]:
    return [p for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts]


def test_programs_run_only_through_the_one_runner() -> None:
    """P1: no subprocess import outside helpers.py and no os process call in src."""
    found = stray_process_violations(_src_files(), SRC)
    lines = [f"{len(found)} P1 violation(s): run the program through interfaces/cli/helpers.py"]
    lines.extend(f"  {v.detail}" for v in found)
    assert not found, "\n".join(lines)


# ---- planted cases -------------------------------------------------------------------------


def _plant(tmp_path: Path, files: dict[str, str]) -> list[Path]:
    paths = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        ("import subprocess\n", "mod.py:1 imports subprocess"),
        ("import subprocess as sp\n", "mod.py:1 imports subprocess"),
        ("from subprocess import run\n", "mod.py:1 imports from subprocess"),
        ("import os\nos.system('x')\n", "mod.py:2 calls os.system"),
        ("import os\nos.popen('x')\n", "mod.py:2 calls os.popen"),
        ("import os\nos.startfile('x')\n", "mod.py:2 calls os.startfile"),
        ("import os\nos.spawnl(0, 'x')\n", "mod.py:2 calls os.spawnl"),
        ("import os\nos.execv('x', [])\n", "mod.py:2 calls os.execv"),
        ("import os\nos.posix_spawn('x', [], {})\n", "mod.py:2 calls os.posix_spawn"),
        ("import os as o\no.system('x')\n", "mod.py:2 calls os.system"),
        ("from os import system as s\ns('x')\n", "mod.py:2 calls os.system"),
    ],
)
def test_p1_stray_process_fires(tmp_path: Path, body: str, detail: str) -> None:
    """Each way of starting a program outside the runner is flagged with its site."""
    found = stray_process_violations(_plant(tmp_path, {"mod.py": body}), tmp_path)
    assert [v.detail for v in found] == [detail]


@pytest.mark.parametrize(
    ("name", "body"),
    [
        (RUNNER, "import subprocess\nsubprocess.run(['x'])\n"),
        ("mod.py", "import os\npid = os.fork()\n"),
        ("mod.py", "import os\nx = os.path.join('a')\n"),
        ("mod.py", "def system():\n    pass\nsystem()\n"),
    ],
)
def test_p1_runner_fork_and_unrelated_names_are_quiet(tmp_path: Path, name: str, body: str) -> None:
    """The runner's own subprocess import, os.fork and an unrelated `system` pass."""
    assert stray_process_violations(_plant(tmp_path, {name: body}), tmp_path) == []
