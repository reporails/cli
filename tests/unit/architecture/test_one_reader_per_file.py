"""One reader function per YAML file.

Every YAML file the cli reads has exactly one reader function, declared in `_READERS`. Three rules,
all pure `ast`:

- R1 stray reader: every reference to `load_yaml_file` or `fast_yaml_load` in `src/reporails_cli/`
  (a call or the function passed or stored, by bare name, through an import alias, or as an
  attribute such as `utils.load_yaml_file(...)`) sits directly inside a `_READERS` function.
  The qualified name is the dotted chain of enclosing classes and functions (`Cls.method`, `outer.inner`);
  a call in a nested function is not inside its outer owner.
  `core/platform/utils/utils.py`, where the YAML reader itself lives, is exempt.
- R2 raw parser: no direct `yaml.load` / `yaml.safe_load` / `yaml.full_load` / `yaml.unsafe_load`
  (or their `_all` forms), as an attribute of `yaml` or of an alias of it, or as a name imported
  from `yaml`, anywhere in `src/reporails_cli/` outside `core/platform/utils/utils.py`.
  `yaml.dump` writes are fine.
- R3 shared file: no two `_READERS` entries name the same file.

Why: a file read in two places is parsed, validated and defaulted two ways, and the copies drift
apart. One reader per file keeps a file's shape in one function.

Each scanner takes the source files and their root (and, for R1/R3, the readers dict), so the
planted tests below run the same code on tmp files.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import pytest

pytestmark = pytest.mark.architecture

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SRC = ROOT / "src" / "reporails_cli"
YAML_UTILS = "core/platform/utils/utils.py"

# "<path under src/reporails_cli>::<qualified function>" -> "<the file it reads>"
_READERS: dict[str, str] = {
    "core/platform/config/config.py::read_config_file": (
        ".ails/config.yml, .ails/config.local.yml, ~/.reporails/config.yml"
    ),
    "core/platform/config/config.py::read_agent_config": "<rules root>/<agent>/config.yml",
    "core/platform/adapters/registry.py::read_checks_document": "<rule>/checks.yml",
    "core/classify/stopwords_sync.py::_read_vocab_file": "<rule>/vocab.yml",
    "core/platform/config/credentials.py::load_credentials_record": "~/.reporails/credentials.yml",
    "core/platform/config/capabilities.py::_matrix_section": "framework/capabilities_matrix.yml",
    "core/platform/config/vocabulary.py::load_capability_vocabulary": "bundled/lexicon/capabilities.yml",
    "core/mapper/lexicon.py::load_dotted_exclusions": "bundled/lexicon/dotted_exclusions.yml",
    "core/mapper/lexicon.py::load_markdown_tokens": "bundled/lexicon/markdown_tokens.yml",
}

_READER_FUNCS = {"load_yaml_file", "fast_yaml_load"}
_RAW_PARSERS = {
    "load",
    "safe_load",
    "full_load",
    "unsafe_load",
    "load_all",
    "safe_load_all",
    "full_load_all",
    "unsafe_load_all",
}


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule and a human line."""

    rule: str
    detail: str


def _rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


@cache
def _parse_cached(path: Path, mtime_ns: int) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _parse(path: Path) -> ast.Module:
    return _parse_cached(path, path.stat().st_mtime_ns)


def _aliases(tree: ast.Module, names: set[str], module: str | None = None) -> dict[str, str]:
    """Local name -> imported name for `from <x> import <name> [as <alias>]` over `names`.

    With `module`, only imports from that module count (`yaml`); otherwise any module.
    """
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if module is not None and node.module != module:
            continue
        for alias in node.names:
            if alias.name in names:
                out[alias.asname or alias.name] = alias.name
    return out


def _calls_with_owner(tree: ast.Module) -> list[tuple[ast.Call, str]]:
    """Every call with the dotted chain of its enclosing classes and functions ('' at module level)."""
    out: list[tuple[ast.Call, str]] = []

    def visit(node: ast.AST, chain: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Call):
                out.append((child, ".".join(chain)))
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, (*chain, child.name))
            else:
                visit(child, chain)

    visit(tree, ())
    return out


def _references_with_owner(tree: ast.Module) -> list[tuple[ast.expr, str]]:
    """Every name or attribute expression with the dotted chain of its enclosing classes and functions.

    An import statement holds no expression, so it is not a reference.
    """
    out: list[tuple[ast.expr, str]] = []

    def visit(node: ast.AST, chain: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.Name, ast.Attribute)):
                out.append((child, ".".join(chain)))
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, (*chain, child.name))
            else:
                visit(child, chain)

    visit(tree, ())
    return out


def stray_reader_violations(sources: list[Path], root: Path, readers: Mapping[str, str]) -> list[Violation]:
    """R1: a reference to a YAML reader (a call, or the function passed or stored) outside a declared reader."""
    out: list[Violation] = []
    for py in sources:
        rel = _rel(py, root)
        if rel == YAML_UTILS:
            continue
        tree = _parse(py)
        local = _aliases(tree, _READER_FUNCS)
        for ref, owner in _references_with_owner(tree):
            if isinstance(ref, ast.Name):
                name = local.get(ref.id, ref.id if ref.id in _READER_FUNCS else "")
            elif ref.attr in _READER_FUNCS:
                name = ref.attr
            else:
                continue
            if name and f"{rel}::{owner}" not in readers:
                out.append(Violation("R1", f"{rel}:{ref.lineno} {owner or '<module>'} calls {name}"))
    return out


def _yaml_module_names(tree: ast.Module) -> set[str]:
    """The local names `yaml` is bound to: `yaml` itself and any `import yaml as <alias>`."""
    names = {"yaml"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.asname for a in node.names if a.name == "yaml" and a.asname)
    return names


def raw_parser_violations(sources: list[Path], root: Path) -> list[Violation]:
    """R2: a direct `yaml.load`-family call outside the YAML utils module."""
    out: list[Violation] = []
    for py in sources:
        rel = _rel(py, root)
        if rel == YAML_UTILS:
            continue
        tree = _parse(py)
        local = _aliases(tree, _RAW_PARSERS, module="yaml")
        modules = _yaml_module_names(tree)
        for call, owner in _calls_with_owner(tree):
            func = call.func
            name = ""
            if isinstance(func, ast.Name) and func.id in local:
                name = f"yaml.{local[func.id]}"
            elif (
                isinstance(func, ast.Attribute)
                and func.attr in _RAW_PARSERS
                and isinstance(func.value, ast.Name)
                and func.value.id in modules
            ):
                name = f"yaml.{func.attr}"
            if name:
                out.append(Violation("R2", f"{rel}:{call.lineno} {owner or '<module>'} calls {name}"))
    return out


def shared_file_violations(readers: Mapping[str, str]) -> list[Violation]:
    """R3: two reader entries that name the same file."""
    by_file: dict[str, list[str]] = {}
    for key, file in readers.items():
        by_file.setdefault(file, []).append(key)
    return [
        Violation("R3", f"{file} is read by {', '.join(sorted(keys))}")
        for file, keys in sorted(by_file.items())
        if len(keys) > 1
    ]


def _src_files() -> list[Path]:
    return [p for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts]


def _format(rule: str, what: str, violations: list[Violation]) -> str:
    lines = [f"{len(violations)} {rule} violation(s): {what}"]
    lines.extend(f"  {v.detail}" for v in violations)
    return "\n".join(lines)


def test_every_yaml_read_sits_in_a_declared_reader() -> None:
    """R1: each load_yaml_file / fast_yaml_load call in src sits directly inside a `_READERS` function."""
    found = stray_reader_violations(_src_files(), SRC, _READERS)
    assert not found, _format("R1", "move the read onto the file's declared reader", found)


def test_no_raw_yaml_parser_outside_the_utils_module() -> None:
    """R2: no direct yaml.load-family call in src outside the YAML utils module."""
    found = raw_parser_violations(_src_files(), SRC)
    assert not found, _format("R2", "read through the file's declared reader", found)


def test_no_two_readers_name_the_same_file() -> None:
    """R3: `_READERS` has one function per file."""
    found = shared_file_violations(_READERS)
    assert not found, _format("R3", "one reader function per file", found)


# ---- planted cases -------------------------------------------------------------------------


def _plant(tmp_path: Path, files: dict[str, str]) -> list[Path]:
    paths = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


_IMPORT = "from pkg.utils import load_yaml_file\n"
_OWNERS = {"mod.py::read_it": "a.yml"}


def test_r1_call_outside_an_owner_fires(tmp_path: Path) -> None:
    """A load_yaml_file call in an unlisted function is flagged with its site and function."""
    sources = _plant(tmp_path, {"mod.py": _IMPORT + "def other():\n    return load_yaml_file(1)\n"})
    found = stray_reader_violations(sources, tmp_path, _OWNERS)
    assert [v.detail for v in found] == ["mod.py:3 other calls load_yaml_file"]


def test_r1_call_inside_an_owner_is_quiet(tmp_path: Path) -> None:
    """The same call inside a declared reader passes, for both reader names."""
    sources = _plant(
        tmp_path,
        {
            "mod.py": _IMPORT
            + "from pkg.utils import fast_yaml_load\ndef read_it():\n    return load_yaml_file(1), fast_yaml_load('')\n"
        },
    )
    assert stray_reader_violations(sources, tmp_path, _OWNERS) == []


def test_r1_call_in_a_function_nested_in_an_owner_fires(tmp_path: Path) -> None:
    """A nested function is not its outer owner."""
    sources = _plant(
        tmp_path,
        {"mod.py": _IMPORT + "def read_it():\n    def inner():\n        return load_yaml_file(1)\n    return inner\n"},
    )
    found = stray_reader_violations(sources, tmp_path, _OWNERS)
    assert [v.detail for v in found] == ["mod.py:4 read_it.inner calls load_yaml_file"]


def test_r1_aliased_import_fires(tmp_path: Path) -> None:
    """`from ... import load_yaml_file as x` does not hide the call."""
    sources = _plant(
        tmp_path, {"mod.py": "from pkg.utils import load_yaml_file as lyf\ndef other():\n    return lyf(1)\n"}
    )
    found = stray_reader_violations(sources, tmp_path, _OWNERS)
    assert [v.detail for v in found] == ["mod.py:3 other calls load_yaml_file"]


def test_r1_attribute_form_fires(tmp_path: Path) -> None:
    """`utils.load_yaml_file(...)` and `utils.fast_yaml_load(...)` are flagged."""
    sources = _plant(
        tmp_path,
        {"mod.py": "from pkg import utils\ndef other():\n    utils.load_yaml_file(1)\n    utils.fast_yaml_load('')\n"},
    )
    found = stray_reader_violations(sources, tmp_path, _OWNERS)
    assert [v.detail for v in found] == [
        "mod.py:3 other calls load_yaml_file",
        "mod.py:4 other calls fast_yaml_load",
    ]


def test_r1_method_owner_is_quiet(tmp_path: Path) -> None:
    """A `Cls.read` entry covers a call in that method, and only that method."""
    sources = _plant(
        tmp_path,
        {
            "mod.py": _IMPORT
            + "class Cls:\n    def read(self):\n        return load_yaml_file(1)\n"
            + "    def other(self):\n        return load_yaml_file(2)\n"
        },
    )
    found = stray_reader_violations(sources, tmp_path, {"mod.py::Cls.read": "a.yml"})
    assert [v.detail for v in found] == ["mod.py:6 Cls.other calls load_yaml_file"]


def test_r1_exempts_the_yaml_utils_module(tmp_path: Path) -> None:
    """The module that holds the YAML reader itself is not scanned."""
    sources = _plant(tmp_path, {YAML_UTILS: "def load_yaml_file(p):\n    return fast_yaml_load(p)\n"})
    assert stray_reader_violations(sources, tmp_path, {}) == []


def test_r2_raw_yaml_parse_fires(tmp_path: Path) -> None:
    """`yaml.safe_load` and a name imported from yaml are flagged; `yaml.dump` is not."""
    sources = _plant(
        tmp_path,
        {
            "a.py": "import yaml\ndef f(s):\n    yaml.dump({})\n    return yaml.safe_load(s)\n",
            "b.py": "from yaml import safe_load_all as sla, dump\ndef g(s):\n    dump({})\n    return sla(s)\n",
            YAML_UTILS: "import yaml\ndef h(s):\n    return yaml.load(s)\n",
        },
    )
    found = raw_parser_violations(sources, tmp_path)
    assert [v.detail for v in found] == [
        "a.py:4 f calls yaml.safe_load",
        "b.py:4 g calls yaml.safe_load_all",
    ]


def test_r1_reference_that_is_not_a_call_fires(tmp_path: Path) -> None:
    """Passing the reader on or storing it is flagged; the import statement is not."""
    sources = _plant(
        tmp_path,
        {
            "mod.py": _IMPORT
            + "def other(paths):\n    f = load_yaml_file\n    return list(map(load_yaml_file, paths)), f\n"
            + "def read_it(paths):\n    return map(load_yaml_file, paths)\n"
        },
    )
    found = stray_reader_violations(sources, tmp_path, _OWNERS)
    assert [v.detail for v in found] == [
        "mod.py:3 other calls load_yaml_file",
        "mod.py:4 other calls load_yaml_file",
    ]


def test_r1_import_alone_is_quiet(tmp_path: Path) -> None:
    """Importing a reader without referencing it outside an owner is not a violation."""
    sources = _plant(tmp_path, {"mod.py": "from pkg.utils import load_yaml_file as lyf\nimport pkg.utils\n"})
    assert stray_reader_violations(sources, tmp_path, _OWNERS) == []


def test_r2_aliased_module_fires(tmp_path: Path) -> None:
    """`import yaml as y; y.safe_load(...)` and `from yaml import safe_load as sl` are flagged."""
    sources = _plant(
        tmp_path,
        {
            "a.py": "import yaml as y\ndef f(s):\n    return y.safe_load(s)\n",
            "b.py": "from yaml import safe_load as sl\ndef g(s):\n    return sl(s)\n",
        },
    )
    found = raw_parser_violations(sources, tmp_path)
    assert [v.detail for v in found] == [
        "a.py:3 f calls yaml.safe_load",
        "b.py:3 g calls yaml.safe_load",
    ]


def test_r3_one_file_two_readers_fires() -> None:
    """A readers dict naming one file twice is flagged; distinct files pass."""
    found = shared_file_violations({"a.py::f": "x.yml", "b.py::g": "x.yml", "c.py::h": "y.yml"})
    assert len(found) == 1 and "x.yml" in found[0].detail and "a.py::f" in found[0].detail
    assert shared_file_violations({"a.py::f": "x.yml", "c.py::h": "y.yml"}) == []
