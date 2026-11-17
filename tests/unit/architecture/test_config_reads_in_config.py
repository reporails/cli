"""Config files are read only under `core/platform/config/`.

One rule, pure `ast`, over every `src/reporails_cli/core/**/*.py` outside `core/platform/config/`:

- C1 config read: any `Name`, `Attribute.attr`, `from ... import` alias name or `getattr(x, "name")`
  string constant equal to `get_project_config`, `get_global_config`, `get_agent_config` or
  `read_config_file`. An aliased module (`import m as cfg; cfg.get_global_config()`) is caught by the
  attribute name. Function-level and `TYPE_CHECKING` imports count, as do `core/platform/adapters/`.
  A string constant equal to a reader name used as a subscript key (`vars(m)['get_project_config']`,
  `m.__dict__[...]`, `globals()[...]`) counts, and so does a `+` concatenation, f-string of literals or
  `"".join([...])` of literals that folds to a reader name (`getattr(m, 'get_' + 'project_config')`).
  There is no allowlist. `get_agent_config` no longer exists (it was split into `bundled_agent_config`
  and `agent_config_at`); the floor keeps the name so the old reader cannot come back.

Why: a config file read in many places is parsed, defaulted and cached many ways. One folder owns the
reads, and core receives the values through the run context.

Known limits: a reader name built from a runtime value (a variable, a call result, an f-string with a
non-literal part, `str.format`, `%`, slicing, `chr`/`bytes` decoding, a name read from data or a file)
passes (`'get_%s_config' % 'project'` and `'get_{}_config'.format('project')` are not folded);
`operator.attrgetter('<reader>')` and `m.__getattribute__('<reader>')` pass, even with a plain literal,
because the string is neither a subscript key nor a `getattr(x, "name")` argument; a bare string
constant that is not a subscript key or a folded expression passes (so a reader name
in a docstring or a table of strings is quiet).

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
CORE_DIR = "core/"
CONFIG_DIR = "core/platform/config/"

READERS = frozenset({"get_project_config", "get_global_config", "get_agent_config", "read_config_file"})


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule and a human line."""

    rule: str
    detail: str


def _fold(node: ast.AST) -> str | None:
    """The string a constant expression folds to: a literal, `+` of folds, an f-string of folds,
    `"".join([...])` of folds. None for anything with a runtime part."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold(node.left), _fold(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        parts = [_fold(v.value if isinstance(v, ast.FormattedValue) else v) for v in node.values]
        return None if None in parts else "".join(str(p) for p in parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.List | ast.Tuple)
    ):
        sep, items = _fold(node.func.value), [_fold(e) for e in node.args[0].elts]
        return None if sep is None or None in items else sep.join(str(i) for i in items)
    return None


def _named_reader(node: ast.AST) -> str | None:
    """The reader name `node` references, or None."""
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and node.slice.value in READERS:
        return str(node.slice.value)
    if isinstance(node, ast.BinOp | ast.JoinedStr | ast.Call) and _fold(node) in READERS:
        return str(_fold(node))
    if isinstance(node, ast.Name) and node.id in READERS:
        return node.id
    if isinstance(node, ast.Attribute) and node.attr in READERS:
        return node.attr
    if isinstance(node, ast.alias) and node.name in READERS:
        return node.name
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value in READERS
    ):
        return str(node.args[1].value)
    return None


def config_read_violations(sources: list[Path], root: Path) -> list[Violation]:
    """C1: a config reader named under `core/` outside `core/platform/config/`."""
    out: list[Violation] = []
    for py in sources:
        rel = py.relative_to(root).as_posix()
        if not rel.startswith(CORE_DIR) or rel.startswith(CONFIG_DIR):
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = _named_reader(node)
            if name is not None:
                out.append(Violation("C1", f"{rel}:{getattr(node, 'lineno', 0)} names {name}"))
    return sorted(out, key=lambda v: v.detail)


def _src_files() -> list[Path]:
    return [p for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts]


def test_config_is_read_only_under_the_config_folder() -> None:
    """C1: no config read under core outside `core/platform/config/`."""
    found = config_read_violations(_src_files(), SRC)
    lines = [f"{len(found)} C1 violation(s): take config values from the run context"]
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
        ("x = get_project_config(root)\n", "core/x/mod.py:1 names get_project_config"),
        (
            "from reporails_cli.core.platform.config.config import get_project_config\n",
            "core/x/mod.py:1 names get_project_config",
        ),
        (
            "import reporails_cli.core.platform.config.config as cfg\ncfg.get_global_config()\n",
            "core/x/mod.py:2 names get_global_config",
        ),
        (
            "def f():\n    from reporails_cli.core.platform.config.config import get_global_config\n",
            "core/x/mod.py:2 names get_global_config",
        ),
        (
            "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from m import read_config_file\n",
            "core/x/mod.py:3 names read_config_file",
        ),
        ("y = getattr(config, 'read_config_file')\n", "core/x/mod.py:1 names read_config_file"),
        ("x = get_agent_config('claude')\n", "core/x/mod.py:1 names get_agent_config"),
    ],
)
def test_c1_config_read_fires(tmp_path: Path, body: str, detail: str) -> None:
    """Each way of naming a config reader under core is flagged with its site."""
    found = config_read_violations(_plant(tmp_path, {"core/x/mod.py": body}), tmp_path)
    assert detail in [v.detail for v in found]


@pytest.mark.parametrize(
    "body",
    [
        "x = vars(cfgmod)['get_project_config'](root)\n",
        "x = cfgmod.__dict__['get_global_config']()\n",
        "x = globals()['read_config_file'](p)\n",
        "x = getattr(cfgmod, 'get_' + 'project_config')(root)\n",
        "x = getattr(cfgmod, f'get_{\"project\"}_config')(root)\n",
        "x = getattr(cfgmod, 'get_' + 'global' + '_config')()\n",
        "x = getattr(cfgmod, ''.join(['read_', 'config_file']))(p)\n",
        "x = getattr(cfgmod, ('get_' + 'agent') + '_config')\n",
        "x = vars(cfgmod)['get_' + 'project_config'](root)\n",
    ],
)
def test_c1_computed_names_fire(tmp_path: Path, body: str) -> None:
    """A reader named by a subscript key or by constants that fold to its name is flagged."""
    found = config_read_violations(_plant(tmp_path, {"core/x/mod.py": body}), tmp_path)
    assert [v.rule for v in found] == ["C1"]


def test_c1_fires_under_adapters(tmp_path: Path) -> None:
    """`core/platform/adapters/` has no exemption."""
    body = "from m import read_config_file\n"
    found = config_read_violations(_plant(tmp_path, {"core/platform/adapters/a.py": body}), tmp_path)
    assert [v.detail for v in found] == ["core/platform/adapters/a.py:1 names read_config_file"]


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("core/platform/config/config.py", "def get_project_config(r): ...\nx = read_config_file(p)\n"),
        ("interfaces/cli/cmd.py", "from m import get_project_config, get_global_config\nget_project_config(r)\n"),
        ("core/x/mod.py", "x = run.project_config(root)\n"),
        ("core/x/mod.py", "p = get_project_config_path(root)\nq = get_global_config_path()\n"),
        ("core/x/mod.py", "project_config = {}\nx = project_config.get('a')\n"),
        ("core/x/mod.py", "y = getattr(config, 'project_config')\n"),
        ("core/x/mod.py", "y = vars(m)['project_config']\nz = d['get_project_config_path']\n"),
        ("core/x/mod.py", "y = getattr(m, 'get_' + 'project_config_path')\n"),
        ("core/x/mod.py", "y = getattr(m, f'get_{n}_config')\nz = ''.join(parts)\n"),
        ("core/x/mod.py", "'get_project_config'\nx = ('get_global_config', 1)\n"),
    ],
)
def test_c1_clean_shapes_are_quiet(tmp_path: Path, name: str, body: str) -> None:
    """The config folder, interfaces, run-context reads, path helpers and plain locals pass."""
    assert config_read_violations(_plant(tmp_path, {name: body}), tmp_path) == []
