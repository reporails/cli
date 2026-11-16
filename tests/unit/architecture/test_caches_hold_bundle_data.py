"""A cache holds only bundled or content-keyed data, never project state.

Pure `ast`, over every `src/reporails_cli/core/**/*.py` and `src/reporails_cli/formatters/**/*.py`
(`interfaces/` owns its process's session state):

- C1 project key: a function decorated with `functools.cache` / `lru_cache` (any alias) fails when a
  parameter annotation names `Path`, `PurePath` or `PathLike` anywhere (strings included), or when its
  body applies `open`, `.open`, `.read_text`, `.read_bytes`, `.iterdir`, `.glob`, `.rglob`, `.walk` or
  `os.scandir|listdir|walk` to an expression naming a parameter.
- C2 bounded: a cached function with a parameter carries an integer `maxsize`; `functools.cache` and
  `maxsize=None` fail. A zero-parameter cache passes.
- C3 immutable result: a cached function's return annotation is not a mutable container (`dict`, `list`,
  `set`, `bytearray`, `defaultdict`, `OrderedDict`, `deque`, bare, subscripted or in a union), nor an
  alias that resolves to one in `core/platform/contract/json_value.py`.
- C4 project-keyed module state: a module-level name bound to a mutable container fails when a `src/`
  statement mutates it (subscript store/delete/augmented assignment, or `append`/`extend`/`insert`/`add`/
  `update`/`setdefault`/`pop`/`popitem`/`remove`/`discard`/`clear`, by bare name or as
  `<module alias>.<NAME>`) and either its annotation names `Path`/`PurePath`, or the mutation sits in a
  function with a `Path`-annotated parameter.

There is no allowlist. Each failure reads `module:line name rule`.

Known limits: a project path turned into a `str` before it reaches a cached function or a container
passes; `ContextVar` values pass; instance attributes of long-lived objects pass; a mutation reached
through an element (`_c[k].append(...)`) or through an alias of the container is not seen; C3 reads the
top of the return annotation (and its union members), not the containers nested inside a `Mapping` or
`tuple`.

Why: a cache keyed on project state serves stale or foreign data to the next run of a long-lived process.
The detectors take the source files and their root, so the planted tests run the same code on tmp files.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.unit.architecture._module_aliases import module_names

pytestmark = pytest.mark.architecture

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SRC = ROOT / "src" / "reporails_cli"
PACKAGE = "reporails_cli"
SCOPE = ("core/", "formatters/")
JSON_VALUE = SRC / "core" / "platform" / "contract" / "json_value.py"

CACHE_NAMES = frozenset({"cache", "lru_cache"})
PATH_TYPES = frozenset({"Path", "PurePath", "PathLike"})
PATH_TEXT = re.compile(r"\b(?:Path|PurePath|PathLike)\b")
MUTABLE_TYPES = frozenset({"dict", "list", "set", "bytearray", "defaultdict", "OrderedDict", "deque"})
CONTAINER_CALLS = MUTABLE_TYPES | {"Counter"}
CONTENT_ATTRS = frozenset({"open", "read_text", "read_bytes", "iterdir", "glob", "rglob", "walk"})
OS_LISTING = frozenset({"scandir", "listdir", "walk"})
MUTATORS = frozenset(
    {"append", "extend", "insert", "add", "update", "setdefault", "pop", "popitem", "remove", "discard", "clear"}
)

Func = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule and a human line `module:line name rule`."""

    rule: str
    detail: str


def _tree(py: Path) -> ast.Module:
    return ast.parse(py.read_text(encoding="utf-8"))


def _in_scope(rel: str) -> bool:
    return rel.startswith(SCOPE)


def _annotation_nodes(annotation: ast.expr | None) -> Iterator[ast.AST]:
    """Every node of an annotation, string annotations parsed in place."""
    if annotation is None:
        return
    for node in ast.walk(annotation):
        yield node
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                yield from ast.walk(ast.parse(node.value, mode="eval").body)
            except SyntaxError:
                continue


def _names_path(annotation: ast.expr | None) -> bool:
    for node in _annotation_nodes(annotation):
        if isinstance(node, ast.Name) and node.id in PATH_TYPES:
            return True
        if isinstance(node, ast.Attribute) and node.attr in PATH_TYPES:
            return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and PATH_TEXT.search(node.value):
            return True
    return False


def _top_names(annotation: ast.expr | None) -> Iterator[str]:
    """The names at the top of an annotation: itself, its subscripted base, its union members."""
    if annotation is None:
        return
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        try:
            yield from _top_names(ast.parse(annotation.value, mode="eval").body)
        except SyntaxError:
            return
    elif isinstance(annotation, ast.Name):
        yield annotation.id
    elif isinstance(annotation, ast.Attribute):
        yield annotation.attr
    elif isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        yield from _top_names(annotation.left)
        yield from _top_names(annotation.right)
    elif isinstance(annotation, ast.Subscript):
        base = next(_top_names(annotation.value), "")
        yield base
        if base in {"Optional", "Union"}:
            members = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
            for member in members:
                yield from _top_names(member)


def mutable_aliases(json_value: Path) -> frozenset[str]:
    """The `type X = ...` aliases of `json_value.py` that resolve to a mutable container."""
    aliases = {n.name.id: n.value for n in _tree(json_value).body if isinstance(n, ast.TypeAlias)}
    found: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, value in aliases.items():
            if name in found:
                continue
            used = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
            if used & (MUTABLE_TYPES | found):
                found.add(name)
                changed = True
    return frozenset(found)


@dataclass(frozen=True)
class _Cache:
    """A cache decorator: whether its `maxsize` is an integer."""

    bounded: bool


def _cache_decorator(tree: ast.Module, node: ast.expr) -> _Cache | None:
    """The cache a decorator applies, or None when it is not `functools.cache` / `lru_cache`."""
    modules = module_names(tree, "functools")
    imported: dict[str, str] = {}
    for stmt in ast.walk(tree):
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "functools":
            for alias in stmt.names:
                if alias.name in CACHE_NAMES:
                    imported[alias.asname or alias.name] = alias.name
    call = node if isinstance(node, ast.Call) else None
    target = call.func if call else node
    kind: str | None = None
    if isinstance(target, ast.Name):
        kind = imported.get(target.id)
    elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id in modules:
        kind = target.attr if target.attr in CACHE_NAMES else None
    if kind is None:
        return None
    if kind == "cache":
        return _Cache(bounded=False)
    if call is None:
        return _Cache(bounded=True)
    size = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "maxsize"), None)
    if size is None:
        return _Cache(bounded=True)
    return _Cache(isinstance(size, ast.Constant) and isinstance(size.value, int) and not isinstance(size.value, bool))


def _params(fn: Func) -> list[ast.arg]:
    a = fn.args
    out = [*a.posonlyargs, *a.args, *a.kwonlyargs]
    out.extend(x for x in (a.vararg, a.kwarg) if x is not None)
    return out


def _names_any(expr: ast.AST, names: set[str]) -> bool:
    return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(expr))


def _applies_listing(fn: Func, names: set[str]) -> bool:
    """A content or listing call applied to an expression naming a parameter."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"open", *OS_LISTING}:
            if node.args and _names_any(node.args[0], names):
                return True
        elif isinstance(func, ast.Attribute):
            if func.attr in CONTENT_ATTRS and _names_any(func.value, names):
                return True
            if func.attr in OS_LISTING and node.args and _names_any(node.args[0], names):
                return True
    return False


def _cache_rules(tree: ast.Module, fn: Func, aliases: frozenset[str]) -> set[str]:
    caches = [c for c in (_cache_decorator(tree, d) for d in fn.decorator_list) if c is not None]
    if not caches:
        return set()
    params = _params(fn)
    names = {p.arg for p in params}
    rules: set[str] = set()
    if any(_names_path(p.annotation) for p in params) or _applies_listing(fn, names):
        rules.add("C1")
    if params and not all(c.bounded for c in caches):
        rules.add("C2")
    if set(_top_names(fn.returns)) & (MUTABLE_TYPES | aliases):
        rules.add("C3")
    return rules


def cache_violations(sources: list[Path], root: Path, aliases: frozenset[str]) -> list[Violation]:
    """C1-C3 over the cached functions of `core/` and `formatters/`."""
    out: list[Violation] = []
    for py in sources:
        rel = py.relative_to(root).as_posix()
        if not _in_scope(rel):
            continue
        tree = _tree(py)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.extend(
                    Violation(rule, f"{rel}:{node.lineno} {node.name} {rule}")
                    for rule in sorted(_cache_rules(tree, node, aliases))
                )
    return sorted(out, key=lambda v: v.detail)


def _dotted(rel: str) -> str:
    parts = rel.removesuffix(".py").split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join([PACKAGE, *parts])


def _is_container(value: ast.expr | None) -> bool:
    if isinstance(value, (ast.Dict, ast.List, ast.Set, ast.DictComp, ast.ListComp, ast.SetComp)):
        return True
    return isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in CONTAINER_CALLS


def _containers(tree: ast.Module) -> dict[str, tuple[int, bool]]:
    """Module-level names bound to a mutable container: name -> (line, annotation names a path)."""
    found: dict[str, tuple[int, bool]] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and _is_container(stmt.value):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = (stmt.lineno, False)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and _is_container(stmt.value):
            found[stmt.target.id] = (stmt.lineno, _names_path(stmt.annotation))
    return found


def _module_aliases(tree: ast.Module, dotted: str, rel: str) -> set[str]:
    """The local names the module `dotted` is bound to in the file `rel`."""
    names = module_names(tree, dotted)
    here = _dotted(rel).split(".")
    package = here if rel.endswith("__init__.py") else here[:-1]
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            base = ".".join(package[: len(package) - node.level + 1])
            origin = ".".join(x for x in (base, node.module) if x)
        else:
            origin = node.module or ""
        names.update(a.asname or a.name for a in node.names if f"{origin}.{a.name}" == dotted)
    return names


def _mutated_target(node: ast.AST) -> ast.expr | None:
    """The expression a statement mutates in place, or None."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in MUTATORS:
        return node.func.value
    targets: list[ast.expr] = []
    if isinstance(node, ast.Assign | ast.Delete):
        targets = list(node.targets)
    elif isinstance(node, ast.AugAssign):
        targets = [node.target]
    for target in targets:
        if isinstance(target, ast.Subscript):
            return target.value
    return None


def _mutations(node: ast.AST, in_path_fn: bool = False) -> Iterator[tuple[ast.expr, bool]]:
    """Every in-place mutation target with whether it sits in a function with a `Path` parameter."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        in_path_fn = in_path_fn or any(_names_path(p.annotation) for p in _params(node))
    target = _mutated_target(node)
    if target is not None:
        yield target, in_path_fn
    for child in ast.iter_child_nodes(node):
        yield from _mutations(child, in_path_fn)


def _hits(target: ast.expr, name: str, own: bool, aliases: set[str]) -> bool:
    if own and isinstance(target, ast.Name):
        return target.id == name
    return (
        isinstance(target, ast.Attribute)
        and target.attr == name
        and isinstance(target.value, ast.Name)
        and target.value.id in aliases
    )


def state_violations(sources: list[Path], root: Path) -> list[Violation]:
    """C4: a project-keyed mutable container at module level of `core/` or `formatters/`."""
    trees = {py.relative_to(root).as_posix(): _tree(py) for py in sources}
    mutations = {rel: list(_mutations(tree)) for rel, tree in trees.items()}
    mutated_names = {
        rel: {t.id if isinstance(t, ast.Name) else t.attr for t, _ in found if isinstance(t, (ast.Name, ast.Attribute))}
        for rel, found in mutations.items()
    }
    out: list[Violation] = []
    for rel, tree in trees.items():
        if not _in_scope(rel):
            continue
        dotted = _dotted(rel)
        for name, (line, path_annotated) in _containers(tree).items():
            for other, other_tree in trees.items():
                if name not in mutated_names[other]:
                    continue
                aliases = _module_aliases(other_tree, dotted, other)
                if any(
                    _hits(target, name, other == rel, aliases) and (path_annotated or in_path_fn)
                    for target, in_path_fn in mutations[other]
                ):
                    out.append(Violation("C4", f"{rel}:{line} {name} C4"))
                    break
    return sorted(out, key=lambda v: v.detail)


def floor_violations(sources: list[Path], root: Path, aliases: frozenset[str]) -> list[Violation]:
    """C1-C4 over `sources`."""
    found = [*cache_violations(sources, root, aliases), *state_violations(sources, root)]
    return sorted(found, key=lambda v: v.detail)


def _src_files() -> list[Path]:
    return [p for p in sorted(SRC.rglob("*.py")) if "__pycache__" not in p.parts]


def test_caches_hold_bundle_data() -> None:
    """C1-C4: no cache or module container keyed on project state under core or formatters."""
    found = floor_violations(_src_files(), SRC, mutable_aliases(JSON_VALUE))
    lines = [f"{len(found)} violation(s): a cache holds bundled or content-keyed data, bounded and immutable"]
    lines.extend(f"  {v.detail}" for v in found)
    assert not found, "\n".join(lines)


# ---- planted cases -------------------------------------------------------------------------

ALIASES = mutable_aliases(JSON_VALUE)


def _plant(tmp_path: Path, files: dict[str, str]) -> list[Path]:
    paths = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths


def _rules(tmp_path: Path, files: dict[str, str]) -> list[str]:
    return [v.rule for v in floor_violations(_plant(tmp_path, files), tmp_path, ALIASES)]


def test_aliases_are_read_from_json_value() -> None:
    """The mutable alias set comes from the file's AST and leaves the scalar alias out."""
    assert {"JsonValue", "JsonObject", "WireValue", "WireObject"} <= ALIASES
    assert "JsonScalar" not in ALIASES


LRU = "from functools import lru_cache\n"


@pytest.mark.parametrize(
    ("rule", "body"),
    [
        ("C1", LRU + "from pathlib import Path\n@lru_cache(maxsize=8)\ndef f(p: Path) -> str:\n    return ''\n"),
        ("C1", LRU + "@lru_cache(maxsize=8)\ndef f(p: 'Path | None') -> str:\n    return ''\n"),
        ("C1", LRU + "@lru_cache(maxsize=8)\ndef f(p: tuple[Path, ...]) -> str:\n    return ''\n"),
        ("C1", LRU + "@lru_cache(maxsize=8)\ndef f(p: str) -> str:\n    return Path(p).read_text()\n"),
        ("C1", LRU + "@lru_cache(maxsize=8)\ndef f(p: str) -> str:\n    return open(p).read()\n"),
        ("C1", LRU + "@lru_cache(maxsize=8)\ndef f(p: str) -> int:\n    return len(os.listdir(p))\n"),
        ("C2", "import functools\n@functools.cache\ndef f(x: str) -> str:\n    return x\n"),
        ("C2", "import functools as ft\n@ft.cache\ndef f(x: str) -> str:\n    return x\n"),
        ("C2", LRU + "@lru_cache(maxsize=None)\ndef f(x: str) -> str:\n    return x\n"),
        ("C3", LRU + "@lru_cache(maxsize=4)\ndef f(x: str) -> dict[str, int]:\n    return {}\n"),
        ("C3", LRU + "@lru_cache(maxsize=4)\ndef f(x: str) -> JsonObject:\n    return {}\n"),
        ("C3", LRU + "@lru_cache(maxsize=4)\ndef f(x: str) -> 'list[str] | None':\n    return None\n"),
        ("C3", LRU + "@lru_cache\ndef f() -> WireObject:\n    return {}\n"),
    ],
)
def test_cache_rule_fires_exactly(tmp_path: Path, rule: str, body: str) -> None:
    """Each planted cache shape produces exactly its rule."""
    assert _rules(tmp_path, {"core/x/mod.py": body}) == [rule]


@pytest.mark.parametrize(
    "body",
    [
        LRU + "@lru_cache(maxsize=4)\ndef f(x: str) -> tuple[str, ...]:\n    return ()\n",
        LRU + "@lru_cache(maxsize=4)\ndef f(x: str) -> frozenset[str]:\n    return frozenset()\n",
        LRU + "@lru_cache(maxsize=4)\ndef f(x: str) -> Mapping[str, int]:\n    return {}\n",
        LRU + "@lru_cache(maxsize=32)\ndef f(path_text: str, mtime_ns: int, size: int) -> Mapping[str, int]:\n"
        "    return {}\n",
        LRU + "@lru_cache(maxsize=1)\ndef f() -> Mapping[str, int]:\n    return {}\n",
        "import functools\n@functools.cache\ndef f() -> Mapping[str, int]:\n    return {}\n",
        "from functools import cached_property\nclass A:\n    @cached_property\n"
        "    def f(self) -> dict[str, int]:\n        return {}\n",
        "def f(p: Path) -> str:\n    return Path(p).read_text()\n",
        "TABLE = {'a': 1}\nx = TABLE['a']\n",
        "_r: dict[str, int] = {}\ndef register(name: str, v: int) -> None:\n    _r[name] = v\n",
    ],
)
def test_clean_shapes_are_quiet(tmp_path: Path, body: str) -> None:
    """Bounded text-keyed caches, zero-arg bundle caches, constants and str-keyed registries pass."""
    assert _rules(tmp_path, {"core/x/mod.py": body}) == []


def test_interfaces_are_out_of_scope(tmp_path: Path) -> None:
    """`interfaces/` owns its process's state."""
    body = "import functools\n@functools.cache\ndef f(x: str) -> dict[str, int]:\n    return {}\n"
    assert _rules(tmp_path, {"interfaces/mcp/s.py": body}) == []


@pytest.mark.parametrize(
    "body",
    [
        "_c: dict[Path, int] = {}\ndef put(k, v):\n    _c[k] = v\n",
        "_c: dict[Path, int] = {}\ndef put(k, v):\n    _c.setdefault(k, v)\n",
        "_c = {}\ndef g(root: Path, v):\n    _c[str(root)] = v\n",
        "_c = set()\ndef g(root: Path):\n    _c.add(str(root))\n",
    ],
)
def test_c4_fires_in_module(tmp_path: Path, body: str) -> None:
    """A path-annotated container, or one mutated in a function with a path parameter, is flagged."""
    assert _rules(tmp_path, {"core/x/mod.py": body}) == ["C4"]


@pytest.mark.parametrize(
    "user",
    [
        "import reporails_cli.core.x.mod as mod\ndef put(k, v):\n    mod._c[k] = v\n",
        "from reporails_cli.core.x import mod\ndef put(k, v):\n    mod._c[k] = v\n",
        "from . import mod\ndef put(k, v):\n    mod._c.update({k: v})\n",
    ],
)
def test_c4_fires_across_modules(tmp_path: Path, user: str) -> None:
    """A mutation as `<module alias>.<NAME>` from another module counts."""
    files = {"core/x/mod.py": "_c: dict[Path, int] = {}\n", "core/x/user.py": user}
    assert _rules(tmp_path, files) == ["C4"]


def test_c4_cross_module_str_keyed_is_quiet(tmp_path: Path) -> None:
    """A str-keyed container mutated from another module passes."""
    files = {
        "core/x/mod.py": "_c: dict[str, int] = {}\n",
        "core/x/user.py": "import reporails_cli.core.x.mod as mod\ndef put(k: str, v):\n    mod._c[k] = v\n",
    }
    assert _rules(tmp_path, files) == []


def test_report_line_names_module_line_name_rule(tmp_path: Path) -> None:
    """A failure reads `module:line name rule`."""
    body = "import functools\n@functools.cache\ndef f(x: str) -> str:\n    return x\n"
    found = floor_violations(_plant(tmp_path, {"core/x/mod.py": body}), tmp_path, ALIASES)
    assert [v.detail for v in found] == ["core/x/mod.py:3 f C2"]
