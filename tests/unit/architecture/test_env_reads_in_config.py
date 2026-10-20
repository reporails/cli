"""Environment variables are read only under `core/platform/config/`.

One rule, pure `ast`, over every `src/reporails_cli/**/*.py` outside `core/platform/config/`:

- E1 env read: a reference to `os.getenv`, `os.getenvb`, `os.environ` or `os.environb` (through
  `import os`, `import os as x` or an attribute chain on either), or `from os import environ`,
  `environb`, `getenv`, `getenvb`. `.get`, `.pop`, `.setdefault`, `.items`, `in os.environ`,
  `os.environ[...]` loads and passing `os.environ` along all count. The one exception is a write:
  `os.environ[...] = value` and `del os.environ[...]` set or remove a variable and read nothing.
  That is a write through a subscript store or delete; a method write (`.update`, `.clear`, `|=`) and
  `os.environ[...] += ...` count as a read.

Why: a variable read in many places is trimmed, defaulted and validated many ways. One folder owns
the reads, so each variable has one meaning.

The scanner takes the source files and their root, so the planted tests below run the same code on
tmp files.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.unit.architecture._os_aliases import os_names

pytestmark = pytest.mark.architecture

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SRC = ROOT / "src" / "reporails_cli"
CONFIG_DIR = "core/platform/config/"

_READ_FUNCS = {"getenv", "getenvb"}
_ENVIRON = {"environ", "environb"}


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule and a human line."""

    rule: str
    detail: str


def _is_write_target(node: ast.Attribute, parents: dict[ast.AST, ast.AST]) -> bool:
    """True when `node` is the object of a subscript store or delete (`os.environ["X"] = "1"`)."""
    parent = parents.get(node)
    if not (isinstance(parent, ast.Subscript) and parent.value is node):
        return False
    # `os.environ["X"] += "..."` reads the value before it writes, so it counts as a read.
    return isinstance(parent.ctx, ast.Del) or (
        isinstance(parent.ctx, ast.Store) and not isinstance(parents.get(parent), ast.AugAssign)
    )


def _reads_env(node: ast.AST, modules: set[str], parents: dict[ast.AST, ast.AST]) -> bool:
    """True for `os.getenv` / `os.environ` (any alias of `os`) used as anything but a write target."""
    if not (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in modules):
        return False
    return node.attr in _READ_FUNCS or (node.attr in _ENVIRON and not _is_write_target(node, parents))


def env_read_violations(sources: list[Path], root: Path) -> list[Violation]:
    """E1: an environment read outside `core/platform/config/`."""
    out: list[Violation] = []
    for py in sources:
        rel = py.relative_to(root).as_posix()
        if rel.startswith(CONFIG_DIR):
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        modules = os_names(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "os":
                out.extend(
                    Violation("E1", f"{rel}:{node.lineno} imports os.{alias.name}")
                    for alias in node.names
                    if alias.name in _READ_FUNCS | _ENVIRON
                )
            elif _reads_env(node, modules, parents):
                out.append(Violation("E1", f"{rel}:{node.lineno} reads os.{getattr(node, 'attr', '')}"))
    return out


def _src_files() -> list[Path]:
    return [p for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts]


def test_environment_is_read_only_under_the_config_folder() -> None:
    """E1: no env read in src outside `core/platform/config/`."""
    found = env_read_violations(_src_files(), SRC)
    lines = [f"{len(found)} E1 violation(s): read the variable through core/platform/config/bootstrap.py"]
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
        ("import os\nx = os.getenv('A')\n", "mod.py:2 reads os.getenv"),
        ("import os\nx = os.getenvb(b'A')\n", "mod.py:2 reads os.getenvb"),
        ("import os\nx = os.environ.get('A')\n", "mod.py:2 reads os.environ"),
        ("import os\nx = os.environ['A']\n", "mod.py:2 reads os.environ"),
        ("import os\nx = 'A' in os.environ\n", "mod.py:2 reads os.environ"),
        ("import os\nx = os.environ.pop('A')\n", "mod.py:2 reads os.environ"),
        ("import os\nx = dict(os.environ)\n", "mod.py:2 reads os.environ"),
        ("import os\nx = os.environb\n", "mod.py:2 reads os.environb"),
        ("from os import environ\n", "mod.py:1 imports os.environ"),
        ("from os import getenv as g\n", "mod.py:1 imports os.getenv"),
        ("import os as x\ny = x.environ\n", "mod.py:2 reads os.environ"),
        ("import os.path\ny = os.getenv('A')\n", "mod.py:2 reads os.getenv"),
        ("import os\nos.environ['PATH'] += ':x'\n", "mod.py:2 reads os.environ"),
        ("import os\nos.environ.update({'A': '1'})\n", "mod.py:2 reads os.environ"),
    ],
)
def test_e1_env_read_fires(tmp_path: Path, body: str, detail: str) -> None:
    """Each way of reading the environment is flagged with its site."""
    found = env_read_violations(_plant(tmp_path, {"mod.py": body}), tmp_path)
    assert [v.detail for v in found] == [detail]


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("mod.py", "import os\nos.environ['A'] = '1'\n"),
        ("mod.py", "import os\ndel os.environ['A']\n"),
        ("mod.py", "import os\nx = os.path.join('a', 'b')\nos.fork\n"),
        ("mod.py", "environ = {}\nx = environ.get('A')\n"),
        ("core/platform/config/mod.py", "import os\nx = os.environ.get('A')\ny = os.getenv('B')\n"),
    ],
)
def test_e1_writes_and_the_config_folder_are_quiet(tmp_path: Path, name: str, body: str) -> None:
    """A subscript write or delete, an unrelated name and the config folder itself pass."""
    assert env_read_violations(_plant(tmp_path, {name: body}), tmp_path) == []
