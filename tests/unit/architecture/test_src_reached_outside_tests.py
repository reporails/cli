"""No `src/` code survives only because a test reaches it.

Reach starts at the code the product runs and follows references; a test reference never counts.
Three rules:

- B1 definitions: a module-level function or class that no reached `src/` context references.
  Roots are the module-level statements of every module (anything but a `def` / `class`), functions
  whose decorator marks an entry (`command`, `callback`, `tool`, `resource`, `prompt`), dunder
  names, the `[project.scripts]` entries of `pyproject.toml`, and a def whose name appears as a
  string constant in a reached context (string dispatch). The failure lists the test modules that
  still reference each unreached def, so they are cleaned up with it.
- B2 record fields: a field of a reached dataclass, pydantic model or NamedTuple that no reached
  context reads. A read is a member load on an instance of the class or a subclass, `getattr(x,
  "field")`, a load on an `Any`-typed value, or wholesale serialization of the class (`asdict`,
  `astuple`, `fields`, `vars`, `replace`, `.model_dump`, `.model_dump_json`, `._asdict`,
  `.__dict__`, `getattr` with a non-constant name) outside `core/cache/`, where a round-trip is
  not a reader. Stores do not count. Types come from mypy, so a same-named attribute on an
  unrelated class is not a read.
- B3 parameters: a defaulted parameter of a reached function or method that is only ever called
  directly (never passed as a value, never with `*args` / `**kwargs`) and that no reached call
  passes by keyword or position. A default nobody overrides is a constant dressed as a parameter.

Why: a function, field or parameter kept alive by a test is code the product never runs, yet it
passes review because it has a passing test. Each scanner takes the package root, so the planted
tests below run the same code on a tmp package. `_ALLOWLIST` is keyed by violation key and carries
the reason a violation is accepted; it starts empty.
"""

from __future__ import annotations

import ast
import time
import tomllib
from collections import defaultdict
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest
from mypy import build
from mypy.main import process_options
from mypy.nodes import (
    ARG_NAMED_OPT,
    ARG_OPT,
    FUNC_NO_INFO,
    ClassDef,
    Decorator,
    Expression,
    FuncDef,
    MemberExpr,
    Node,
    OverloadedFuncDef,
    TypeInfo,
    Var,
)
from mypy.traverser import NameAndMemberCollector
from mypy.types import (
    AnyType,
    CallableType,
    Instance,
    Overloaded,
    TupleType,
    Type,
    TypeType,
    UnionType,
    get_proper_type,
)

ROOT = Path(__file__).resolve().parent.parent.parent.parent
PKG = ROOT / "src" / "reporails_cli"
TESTS = ROOT / "tests"
PYPROJECT = ROOT / "pyproject.toml"
CACHE_DIR = "core/cache/"

_ALLOWLIST: dict[str, str] = {}

_ENTRY_DECORATORS = ("command", "callback", "tool", "resource", "prompt")
_WHOLESALE_FUNCS = {
    "dataclasses.asdict",
    "dataclasses.astuple",
    "dataclasses.fields",
    "dataclasses.replace",
    "builtins.vars",
}
_WHOLESALE_MEMBERS = {"model_dump", "model_dump_json", "_asdict", "__dict__"}

Context = tuple[str, str]
Position = tuple[int, int, int | None, int | None]
MODULE_BODY = "<module>"


@dataclass(frozen=True)
class Violation:
    """One floor violation: the rule, a stable allowlist key, and a human reason."""

    rule: str
    key: str
    detail: str


# ---- B1: module index and reach ------------------------------------------------------------


def _modname(path: Path, base: Path) -> str:
    parts = list(path.relative_to(base).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


class _Module:
    """One parsed module: its module-level defs and import bindings."""

    def __init__(self, path: Path, base: Path, is_src: bool) -> None:
        self.path = path
        self.is_src = is_src
        self.name = _modname(path, base)
        self.tree = ast.parse(path.read_text(encoding="utf-8"))
        self.is_pkg = path.name == "__init__.py"
        self.defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef] = {
            node.name: node
            for node in self.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        self.imports: dict[str, tuple[str, ...]] = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.imports[alias.asname] = ("mod", alias.name)
                    else:
                        head = alias.name.split(".")[0]
                        self.imports[head] = ("mod", head)
            elif isinstance(node, ast.ImportFrom):
                source = self.resolve_from(node)
                for alias in node.names:
                    self.imports[alias.asname or alias.name] = ("from", source, alias.name)

    def resolve_from(self, node: ast.ImportFrom) -> str:
        """Absolute dotted module a `from ... import` statement names."""
        if node.level == 0:
            return node.module or ""
        parts = self.name.split(".")
        if not self.is_pkg:
            parts = parts[:-1]
        if node.level > 1:
            parts = parts[: -(node.level - 1)]
        return ".".join(parts + ([node.module] if node.module else []))

    def contexts(self) -> Iterator[tuple[Context, ast.AST]]:
        """Each top-level def, plus everything else at module level as one body context."""
        rest = [n for n in self.tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        yield (self.name, MODULE_BODY), ast.Module(body=rest, type_ignores=[])
        for name, node in self.defs.items():
            yield (self.name, name), node


def _load(root: Path, base: Path, is_src: bool) -> dict[str, _Module]:
    mods = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" not in path.parts:
            module = _Module(path, base, is_src)
            mods[module.name] = module
    return mods


class _Index:
    """Name resolution across the modules of one package."""

    def __init__(self, pkg_root: Path) -> None:
        self.mods = _load(pkg_root, pkg_root.parent, True)

    def resolve_in(self, modn: str, name: str, depth: int = 0) -> Context | None:
        """The (module, def) a name denotes in module `modn`, following `from` imports."""
        module = self.mods.get(modn)
        if module is None or depth > 8:
            return None
        if name in module.defs:
            return (module.name, name)
        imp = module.imports.get(name)
        if imp and imp[0] == "from" and imp[1] in self.mods:
            return self.resolve_in(imp[1], imp[2], depth + 1)
        return None

    def lookup(self, module: _Module, name: str) -> Context | None:
        """Resolve a bare name used in `module` (src or test) to a src def."""
        if module.is_src and name in module.defs:
            return (module.name, name)
        imp = module.imports.get(name)
        if imp and imp[0] == "from" and imp[1] in self.mods:
            return self.resolve_in(imp[1], imp[2])
        return None

    def _dotted_target(self, module: _Module, node: ast.Attribute) -> Context | None:
        chain = [node.attr]
        value: ast.expr = node.value
        while isinstance(value, ast.Attribute):
            chain.append(value.attr)
            value = value.value
        if not isinstance(value, ast.Name):
            return None
        imp = module.imports.get(value.id)
        if imp is None:
            return None
        if imp[0] == "mod":
            prefix = imp[1]
        elif f"{imp[1]}.{imp[2]}" in self.mods:
            prefix = f"{imp[1]}.{imp[2]}"
        else:
            return None
        parts = [prefix, *reversed(chain)]
        for cut in range(len(parts) - 1, 0, -1):
            modn = ".".join(parts[:cut])
            if modn in self.mods:
                return self.resolve_in(modn, parts[cut])
        return None

    def refs(self, module: _Module, node: ast.AST, with_imports: bool = False) -> set[Context]:
        """Src defs a subtree references by name, by attribute on a module, or (optionally) by import."""
        out: set[Context] = set()
        for sub in ast.walk(node):
            target: Context | None = None
            if isinstance(sub, ast.Name):
                target = self.lookup(module, sub.id)
            elif isinstance(sub, ast.Attribute):
                target = self._dotted_target(module, sub)
            elif with_imports and isinstance(sub, ast.ImportFrom):
                source = module.resolve_from(sub)
                for alias in sub.names:
                    hit = self.resolve_in(source, alias.name) if source in self.mods else None
                    if hit:
                        out.add(hit)
            if target:
                out.add(target)
        return out


def _entry_decorated(node: ast.AST) -> bool:
    decorators = getattr(node, "decorator_list", [])
    return any(word in ast.unparse(d) for d in decorators for word in _ENTRY_DECORATORS)


def _strings(node: ast.AST) -> set[str]:
    return {n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _assign_targets(node: ast.Assign | ast.AnnAssign | ast.AugAssign) -> list[ast.expr]:
    return node.targets if isinstance(node, ast.Assign) else [node.target]


def _body_without_all(node: ast.AST) -> ast.AST:
    """A module-body context minus `__all__` assignments, which list names rather than use them."""
    if not isinstance(node, ast.Module):
        return node
    kept = [
        n
        for n in node.body
        if not (
            isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
            and any(isinstance(t, ast.Name) and t.id == "__all__" for t in _assign_targets(n))
        )
    ]
    return ast.Module(body=kept, type_ignores=[])


def _script_roots(pyproject: Path | None) -> set[Context]:
    if pyproject is None or not pyproject.is_file():
        return set()
    project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
    specs = [*project.get("scripts", {}).values()]
    for group in project.get("entry-points", {}).values():
        specs.extend(group.values())
    roots: set[Context] = set()
    for spec in specs:
        module, _, func = spec.partition(":")
        roots.add((module, func.split(".")[0]))
    return roots


def _scripts_dir(pkg_root: Path) -> Path:
    """The maintainer/release scripts folder: `<repo root>/scripts`, the repo root being the parent of `src/`."""
    return pkg_root.parent.parent / "scripts"


def _script_files(pkg_root: Path) -> list[Path]:
    folder = _scripts_dir(pkg_root)
    return sorted(folder.glob("*.py")) if folder.is_dir() else []


def _script_refs(index: _Index, pkg_root: Path) -> set[Context]:
    """Src defs the maintainer scripts reference: scripts are callers, never scanned for their own defs."""
    folder = _scripts_dir(pkg_root)
    out: set[Context] = set()
    if folder.is_dir():
        for script in _load(folder, folder, False).values():
            out |= index.refs(script, script.tree, with_imports=True)
    return out


def reached_contexts(pkg_root: Path, pyproject: Path | None = None) -> set[Context]:
    """Every (module, def | `<module>`) context reachable from the roots, tests ignored."""
    index = _Index(pkg_root)
    graph: dict[Context, set[Context]] = defaultdict(set)
    strings: dict[Context, set[str]] = {}
    roots: set[Context] = {(m.name, MODULE_BODY) for m in index.mods.values()}
    names: dict[str, list[Context]] = defaultdict(list)
    for module in index.mods.values():
        for ctx, node in module.contexts():
            refs = index.refs(module, node)
            refs.discard(ctx)
            graph[ctx] |= refs
            strings[ctx] = _strings(_body_without_all(node))
        for name, node in module.defs.items():
            names[name].append((module.name, name))
            if _entry_decorated(node) or (name.startswith("__") and name.endswith("__")):
                roots.add((module.name, name))
    roots |= _script_roots(pyproject) | _script_refs(index, pkg_root)
    reached: set[Context] = set()
    stack = list(roots)
    while stack:
        ctx = stack.pop()
        if ctx in reached:
            continue
        reached.add(ctx)
        stack.extend(graph.get(ctx, ()))
        for text in strings.get(ctx, ()):
            stack.extend(names.get(text, ()))
    return reached


def unreached_definitions(pkg_root: Path, tests_root: Path | None, pyproject: Path | None = None) -> list[Violation]:
    """B1: module-level defs no reached src context references, with the tests that still do."""
    index = _Index(pkg_root)
    reached = reached_contexts(pkg_root, pyproject)
    test_refs: dict[Context, set[str]] = defaultdict(set)
    if tests_root is not None and tests_root.is_dir():
        for test in _load(tests_root, tests_root.parent, False).values():
            for target in index.refs(test, test.tree, with_imports=True):
                test_refs[target].add(test.name)
    out: list[Violation] = []
    for module in index.mods.values():
        for name, node in module.defs.items():
            if (module.name, name) in reached:
                continue
            where = sorted(test_refs.get((module.name, name), ()))
            site = f"{module.path.relative_to(pkg_root.parent).as_posix()}:{node.lineno}"
            tests = f"referenced by tests: {', '.join(where)}" if where else "no test references it"
            out.append(Violation("B1", f"B1 {module.name}.{name}", f"{module.name}.{name} ({site}) unreached; {tests}"))
    return sorted(out, key=lambda v: v.key)


# ---- B2 / B3: typed reach ------------------------------------------------------------------


def _instances(typ: Type) -> Iterator[Instance]:
    proper = get_proper_type(typ)
    if isinstance(proper, UnionType):
        for item in proper.items:
            yield from _instances(item)
    elif isinstance(proper, Instance):
        yield proper
    elif isinstance(proper, TupleType):
        yield proper.partial_fallback
    elif isinstance(proper, TypeType):
        yield from _instances(proper.item)


def _top_contexts(tree: Node) -> Iterator[tuple[str, Node]]:
    for node in tree.defs:  # type: ignore[attr-defined]
        if isinstance(node, (FuncDef, ClassDef, OverloadedFuncDef)):
            yield node.name, node
        elif isinstance(node, Decorator):
            yield node.func.name, node
        else:
            yield MODULE_BODY, node


def _entry_functions(tree: ast.Module, modname: str) -> set[str]:
    """Fully qualified names of entry-decorated functions and methods in a module."""
    out: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _entry_decorated(node):
            out.add(f"{modname}.{node.name}")
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and _entry_decorated(sub):
                    out.add(f"{modname}.{node.name}.{sub.name}")
    return out


def _definition_name(expr: Expression, types: dict[Expression, Type]) -> str | None:
    """Fully qualified name of the function or class a name/member expression denotes."""
    node = getattr(expr, "node", None)
    if isinstance(node, Decorator):
        return node.func.fullname
    if isinstance(node, (FuncDef, OverloadedFuncDef, TypeInfo)):
        return node.fullname
    typ = get_proper_type(types[expr]) if expr in types else None
    if isinstance(typ, CallableType) and typ.definition is not None:
        return typ.definition.fullname
    if isinstance(typ, Overloaded) and typ.items and typ.items[0].definition is not None:
        return typ.items[0].definition.fullname
    return None


@dataclass
class _Facts:
    """What reached contexts do with records and callables, as mypy sees it."""

    field_reads: set[tuple[str, str]]
    wholesale: set[str]
    passed: dict[str, set[str]]
    called: set[str]
    escapes: set[str]
    splat: set[str]
    own: set[str]


def _collect_facts(
    graph: dict[str, object], pkg_root: Path, reached: set[Context], types: dict[Expression, Type]
) -> _Facts:
    own = {name for name, state in graph.items() if _under(Path(state.xpath), pkg_root)}  # type: ignore[attr-defined]
    facts = _Facts(set(), set(), defaultdict(set), set(), set(), set(), own)
    scripts = _scripts_dir(pkg_root)
    for modname, state in graph.items():
        tree = getattr(state, "tree", None)
        xpath = Path(state.xpath)  # type: ignore[attr-defined]
        is_script = tree is not None and _under(xpath, scripts)
        if tree is None or not (modname in own or is_script):
            continue
        in_cache = modname in own and xpath.resolve().relative_to(pkg_root.resolve()).as_posix().startswith(CACHE_DIR)
        pyast = ast.parse(Path(state.xpath).read_text(encoding="utf-8"))  # type: ignore[attr-defined]
        stores: set[Position] = set()
        calls_at: dict[Position, ast.Call] = {}
        for node in ast.walk(pyast):
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                stores.add((node.lineno, node.col_offset, node.end_lineno, node.end_col_offset))
            if isinstance(node, ast.Call):
                f = node.func
                calls_at[(f.lineno, f.col_offset, f.end_lineno, f.end_col_offset)] = node
        for ctx_name, ctx_node in _top_contexts(tree):
            if is_script or (modname, ctx_name) in reached:
                _scan_context(facts, ctx_node, types, stores, calls_at, in_cache)
    return facts


def _under(path: Path, root: Path) -> bool:
    return root.resolve() in path.resolve().parents


def _arg_infos(
    arg: ast.expr, by_pos: Mapping[Position, Expression], types: Mapping[Expression, Type]
) -> Iterator[TypeInfo]:
    """Classes an argument expression evaluates to: a typed name/member, or a call of a class/function."""
    if isinstance(arg, ast.Call):
        callee = by_pos.get((arg.func.lineno, arg.func.col_offset, arg.func.end_lineno, arg.func.end_col_offset))
        node = getattr(callee, "node", None)
        if isinstance(node, TypeInfo):
            yield node
        elif callee is not None and callee in types:
            ret = get_proper_type(types[callee])
            if isinstance(ret, CallableType):
                for inst in _instances(ret.ret_type):
                    yield inst.type
        return
    expr = by_pos.get((arg.lineno, arg.col_offset, arg.end_lineno, arg.end_col_offset))
    if expr is not None and expr in types:
        for inst in _instances(types[expr]):
            yield inst.type


def _scan_context(
    facts: _Facts,
    ctx_node: Node,
    types: dict[Expression, Type],
    stores: set[Position],
    calls_at: dict[Position, ast.Call],
    in_cache: bool,
) -> None:
    visitor = NameAndMemberCollector()
    ctx_node.accept(visitor)
    by_pos = {(e.line, e.column, e.end_line, e.end_column): e for e in [*visitor.member_exprs, *visitor.name_exprs]}

    for pos, expr in by_pos.items():
        if isinstance(expr, MemberExpr) and pos not in stores and expr.expr in types:
            _record_member_read(facts, expr, types, in_cache)
        target = _definition_name(expr, types)
        if target is None:
            continue
        call = calls_at.get(pos)
        if call is None:
            facts.escapes.add(target)
            continue
        _record_call(facts, target, call)
        if not call.args or in_cache:
            continue
        if target in _WHOLESALE_FUNCS:
            for info in _arg_infos(call.args[0], by_pos, types):
                facts.wholesale.update(b.fullname for b in info.mro if b.module_name in facts.own)
        elif target == "builtins.getattr" and len(call.args) >= 2:
            _record_getattr(facts, call, list(_arg_infos(call.args[0], by_pos, types)))


def _record_member_read(facts: _Facts, expr: MemberExpr, types: dict[Expression, Type], in_cache: bool) -> None:
    if isinstance(get_proper_type(types[expr.expr]), AnyType):
        facts.field_reads.add(("<any>", expr.name))
    for inst in _instances(types[expr.expr]):
        for base in inst.type.mro:
            facts.field_reads.add((base.fullname, expr.name))
            if expr.name in _WHOLESALE_MEMBERS and not in_cache and base.module_name in facts.own:
                facts.wholesale.add(base.fullname)


def _record_call(facts: _Facts, target: str, call: ast.Call) -> None:
    facts.called.add(target)
    if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        facts.splat.add(target)
    facts.passed[target].add(f"#pos{len(call.args)}")
    facts.passed[target].update(k.arg for k in call.keywords if k.arg)


def _record_getattr(facts: _Facts, call: ast.Call, subjects: list[TypeInfo]) -> None:
    name_arg = call.args[1]
    constant = isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str)
    for info in subjects:
        for base in info.mro:
            if constant:
                facts.field_reads.add((base.fullname, str(getattr(name_arg, "value", ""))))
            elif base.module_name in facts.own:
                facts.wholesale.add(base.fullname)


def _is_record(info: TypeInfo) -> bool:
    return (
        "dataclass" in info.metadata
        or "dataclass_tag" in info.metadata
        or info.is_named_tuple
        or any(b.fullname == "pydantic.main.BaseModel" for b in info.mro)
    )


def _unread_fields(graph: dict[str, object], pkg_root: Path, reached: set[Context], facts: _Facts) -> list[Violation]:
    out: list[Violation] = []
    for modname, state in graph.items():
        tree = getattr(state, "tree", None)
        if tree is None or not _under(Path(state.xpath), pkg_root):  # type: ignore[attr-defined]
            continue
        for name, symbol in tree.names.items():
            info = symbol.node
            if not isinstance(info, TypeInfo) or info.fullname != f"{modname}.{name}" or not _is_record(info):
                continue
            if (modname, name) not in reached or any(b.fullname in facts.wholesale for b in info.mro):
                continue
            for field, member in info.names.items():
                node = member.node
                if not isinstance(node, Var) or node.is_classvar or field.startswith("_") or "-" in field:
                    continue
                if node.is_property or field == "model_config":
                    continue
                if (info.fullname, field) in facts.field_reads or ("<any>", field) in facts.field_reads:
                    continue
                out.append(Violation("B2", f"B2 {info.fullname}.{field}", f"{info.fullname}.{field} is never read"))
    return out


def _methods(node: Node) -> Iterator[FuncDef]:
    if isinstance(node, FuncDef):
        yield node
    elif isinstance(node, Decorator):
        yield node.func
    elif isinstance(node, ClassDef):
        for item in node.defs.body:
            if isinstance(item, FuncDef):
                yield item
            elif isinstance(item, Decorator):
                yield item.func


def _call_keys(func: FuncDef, is_method: bool) -> set[str]:
    """The call targets that pass `func`'s arguments: itself, and for a written `__init__` its class
    (`Conn(...)`). Empty for a dataclass's generated `__init__`: it takes the fields, whose defaults B2 owns."""
    if not (is_method and func.name == "__init__"):
        return {func.fullname}
    symbol = func.info.names.get("__init__")
    if symbol is not None and symbol.plugin_generated:
        return set()
    return {func.fullname, func.info.fullname}


def _unpassed_parameters(
    graph: dict[str, object], pkg_root: Path, reached: set[Context], facts: _Facts
) -> list[Violation]:
    out: list[Violation] = []
    for modname, state in graph.items():
        tree = getattr(state, "tree", None)
        if tree is None or not _under(Path(state.xpath), pkg_root):  # type: ignore[attr-defined]
            continue
        entries = _entry_functions(ast.parse(Path(state.xpath).read_text(encoding="utf-8")), modname)  # type: ignore[attr-defined]
        for ctx_name, ctx_node in _top_contexts(tree):
            if (modname, ctx_name) not in reached:
                continue
            for func in _methods(ctx_node):
                is_method = func.info is not FUNC_NO_INFO and isinstance(func.info, TypeInfo) and not func.is_static
                keys = _call_keys(func, is_method)
                if not keys or func.fullname in entries or keys & facts.escapes or keys & facts.splat:
                    continue
                if not keys & facts.called:
                    continue
                seen = set().union(*(facts.passed[key] for key in keys))
                offset = 1 if is_method else 0
                max_pos = max((int(x[4:]) for x in seen if x.startswith("#pos")), default=0)
                for index, (arg, kind) in enumerate(zip(func.arguments, func.arg_kinds, strict=True)):
                    if kind not in (ARG_OPT, ARG_NAMED_OPT):
                        continue
                    pname = arg.variable.name
                    if pname in seen or (kind == ARG_OPT and max_pos > index - offset):
                        continue
                    out.append(
                        Violation("B3", f"B3 {func.fullname}({pname})", f"{func.fullname}({pname}) is never passed")
                    )
    return out


def typed_reach_violations(
    pkg_root: Path, reached: set[Context], config_file: Path
) -> tuple[list[Violation], list[Violation]]:
    """B2 and B3 over one mypy build of `pkg_root`: (unread record fields, never-passed parameters)."""
    targets = [str(pkg_root), *map(str, _script_files(pkg_root))]
    files, options = process_options(["--config-file", str(config_file), *targets], require_targets=True)
    options.export_types = True
    options.incremental = False
    options.preserve_asts = True
    result = build.build(files, options)
    graph: dict[str, object] = {**result.graph}
    types = result.types
    facts = _collect_facts(graph, pkg_root, reached, types)
    fields = sorted(_unread_fields(graph, pkg_root, reached, facts), key=lambda v: v.key)
    params = sorted(_unpassed_parameters(graph, pkg_root, reached, facts), key=lambda v: v.key)
    return fields, params


# ---- real-src tests ------------------------------------------------------------------------


def _format(title: str, violations: list[Violation], hint: str) -> str:
    lines = [f"{len(violations)} {title}:"]
    lines.extend(f"  {v.detail}" for v in violations)
    lines.append(hint)
    return "\n".join(lines)


def _allowed(violations: list[Violation]) -> list[Violation]:
    return [v for v in violations if v.key not in _ALLOWLIST]


@pytest.fixture(scope="module")
def real_typed_scan() -> tuple[list[Violation], list[Violation], float]:
    """One mypy build of the real package, shared by the B2 and B3 tests."""
    start = time.time()
    reached = reached_contexts(PKG, PYPROJECT)
    fields, params = typed_reach_violations(PKG, reached, PYPROJECT)
    return _allowed(fields), _allowed(params), time.time() - start


@pytest.mark.architecture
def test_b1_every_src_definition_is_reached_outside_tests() -> None:
    """No module-level function or class lives only because a test references it."""
    violations = _allowed(unreached_definitions(PKG, TESTS, PYPROJECT))
    assert not violations, _format(
        "unreached src definition(s) (B1)",
        violations,
        "Delete the definition and the tests that exercise only it, or wire it into a product path.",
    )


@pytest.mark.architecture
def test_b2_every_record_field_is_read_by_reached_code(
    real_typed_scan: tuple[list[Violation], list[Violation], float],
) -> None:
    """No dataclass / pydantic / NamedTuple field exists only to be filled."""
    fields = real_typed_scan[0]
    assert not fields, _format(
        "record field(s) no reached context reads (B2)",
        fields,
        "Remove the field and the work that fills it, or read it in a product path.",
    )


@pytest.mark.architecture
def test_b3_every_defaulted_parameter_is_passed_by_a_reached_call(
    real_typed_scan: tuple[list[Violation], list[Violation], float],
) -> None:
    """No defaulted parameter is a constant no reached call ever overrides."""
    params = real_typed_scan[1]
    assert not params, _format(
        "defaulted parameter(s) no reached call passes (B3)",
        params,
        "Inline the default, or pass the parameter from a product path.",
    )


# ---- planted cases -------------------------------------------------------------------------

_PLANT_MYPY_INI = "[mypy]\nignore_missing_imports = True\n"

_PLANT_FILES = {
    "__init__.py": "",
    "app.py": (
        "from dataclasses import asdict\n"
        "from plant.logic import used, Rec, Thing, Row, Whole, helper_default, Svc, Conn\n"
        "from plant import dispatch\n"
        "from plant.scripted import helper_script_arg\n"
        "import plant.util as util\n"
        "def main() -> None:\n"
        "    used()\n"
        "    r = Rec(a=1, b=2, c=3)\n"
        "    print(r.a)\n"
        "    t = Thing(x=1)\n"
        "    t.y = 5\n"
        "    print(t.x)\n"
        "    row = Row(left=1, right=2, unused=3)\n"
        "    print(row.left, row._asdict())\n"
        "    print(asdict(Whole(kept=1, dumped=2)))\n"
        "    helper_default(1, passed=True)\n"
        "    Svc().run(1, 2)\n"
        "    print(Conn(key='k').timeout)\n"
        "    helper_script_arg(1)\n"
        "    util.shared()\n"
        "    dispatch.go('target')\n"
        "main()\n"
    ),
    "logic.py": (
        "from dataclasses import dataclass\n"
        "from typing import NamedTuple\n"
        "def used() -> int:\n    return 1\n"
        "def only_tests_use() -> int:\n    return 2\n"
        "class OnlyTests:\n    pass\n"
        "@dataclass\nclass Rec:\n    a: int\n    b: int\n    c: int\n"
        "@dataclass\nclass Thing:\n    x: int\n    y: int = 0\n"
        "class Row(NamedTuple):\n    left: int\n    right: int\n    unused: int = 0\n"
        "@dataclass\nclass Whole:\n    kept: int\n    dumped: int\n"
        "def helper_default(value: int, passed: bool = False, never: int = 3) -> int:\n"
        "    return value + never + int(passed)\n"
        "class Svc:\n"
        "    def run(self, first: int, second: int = 0, third: int = 9) -> int:\n"
        "        return first + second + third\n"
        "class Conn:\n"
        "    def __init__(self, key: str = '', timeout: float = 30.0) -> None:\n"
        "        self.key = key\n"
        "        self.timeout = timeout\n"
    ),
    "scripted.py": (
        "def only_scripts_use() -> int:\n    return 5\n"
        "def helper_script_arg(value: int, extra: int = 0) -> int:\n    return value + extra\n"
    ),
    "util.py": "def shared() -> int:\n    return 1\n\ndef orphan() -> int:\n    return 2\n",
    "dispatch.py": (
        "def go(name: str) -> object:\n    return globals()[name]\n"
        "def target() -> int:\n    return 3\n"
        "def not_named() -> int:\n    return 4\n"
    ),
}

_PLANT_ENTRY = (
    "import typer\napp = typer.Typer()\n"
    "@app.command()\ndef cli_entry(flag: bool = False) -> None:\n    print(flag)\n"
    "@some.callback()\ndef cb() -> None:\n    pass\n"
)

_PLANT_SCRIPT = (
    "from plant.scripted import only_scripts_use, helper_script_arg\n"
    "def run() -> int:\n    return only_scripts_use() + helper_script_arg(1, extra=2)\n"
    "run()\n"
)


class _Plant:
    """A tmp package with its tests dir, pyproject and mypy config."""

    def __init__(self, root: Path) -> None:
        self.pkg = root / "src" / "plant"
        self.tests = root / "tests"
        self.pyproject = root / "pyproject.toml"
        self.config = root / "mypy.ini"
        self.pkg.mkdir(parents=True)
        self.tests.mkdir()
        for name, text in _PLANT_FILES.items():
            (self.pkg / name).write_text(text, encoding="utf-8")
        (self.pkg / "entry.py").write_text(_PLANT_ENTRY, encoding="utf-8")
        (self.tests / "test_things.py").write_text(
            "from plant.logic import only_tests_use, OnlyTests, used\n"
            "from plant import util\n"
            "def test_it():\n    only_tests_use()\n    OnlyTests()\n    util.orphan()\n    used()\n",
            encoding="utf-8",
        )
        self.scripts = root / "scripts"
        self.scripts.mkdir()
        (self.scripts / "tool.py").write_text(_PLANT_SCRIPT, encoding="utf-8")
        self.pyproject.write_text(
            '[project]\nname = "plant"\n[project.scripts]\nplant = "plant.entry:cli_entry"\n', encoding="utf-8"
        )
        self.config.write_text(_PLANT_MYPY_INI, encoding="utf-8")


@pytest.fixture(scope="module")
def plant(tmp_path_factory: pytest.TempPathFactory) -> _Plant:
    """The planted package, built once for the B1/B2/B3 cases."""
    return _Plant(tmp_path_factory.mktemp("plant"))


@pytest.fixture(scope="module")
def plant_typed(plant: _Plant) -> tuple[set[str], set[str]]:
    """Keys of the B2 and B3 violations of the planted package (one small mypy build)."""
    reached = reached_contexts(plant.pkg, plant.pyproject)
    fields, params = typed_reach_violations(plant.pkg, reached, plant.config)
    return {v.key for v in fields}, {v.key for v in params}


@pytest.mark.architecture
def test_b1_flags_a_def_only_tests_use_and_lists_the_tests(plant: _Plant) -> None:
    """A def, class and module function nothing in src references fail, naming the test module."""
    found = {v.key: v.detail for v in unreached_definitions(plant.pkg, plant.tests, plant.pyproject)}
    assert set(found) == {
        "B1 plant.logic.only_tests_use",
        "B1 plant.logic.OnlyTests",
        "B1 plant.util.orphan",
        "B1 plant.dispatch.not_named",
    }
    assert "tests.test_things" in found["B1 plant.logic.only_tests_use"]
    assert "no test references it" in found["B1 plant.dispatch.not_named"]


@pytest.mark.architecture
def test_b1_counts_production_use_entry_points_and_string_dispatch(plant: _Plant) -> None:
    """A def used by src, a script target, a decorated callback and a string-named def are reached."""
    reached = reached_contexts(plant.pkg, plant.pyproject)
    for context in (
        ("plant.logic", "used"),
        ("plant.util", "shared"),
        ("plant.entry", "cli_entry"),
        ("plant.entry", "cb"),
        ("plant.dispatch", "target"),
    ):
        assert context in reached


@pytest.mark.architecture
def test_b1_counts_a_maintainer_script_reference_as_reach(plant: _Plant) -> None:
    """A def only `scripts/tool.py` uses is reached; the script's own defs are never scanned."""
    assert ("plant.scripted", "only_scripts_use") in reached_contexts(plant.pkg, plant.pyproject)
    keys = {v.key for v in unreached_definitions(plant.pkg, plant.tests, plant.pyproject)}
    assert not {k for k in keys if "scripted" in k or "tool" in k}


@pytest.mark.architecture
def test_b1_test_references_never_count_as_reach(plant: _Plant) -> None:
    """Removing the tests dir changes only the report, never the reached set."""
    with_tests = {v.key for v in unreached_definitions(plant.pkg, plant.tests, plant.pyproject)}
    without = {v.key for v in unreached_definitions(plant.pkg, None, plant.pyproject)}
    assert with_tests == without


@pytest.mark.architecture
def test_b2_flags_unread_fields_and_accepts_reads_and_serialization(plant_typed: tuple[set[str], set[str]]) -> None:
    """Unread fields fail; a loaded field, a store-only field, wholesale `asdict` / `_asdict` handling."""
    fields, _ = plant_typed
    assert fields == {
        "B2 plant.logic.Rec.b",
        "B2 plant.logic.Rec.c",
        "B2 plant.logic.Thing.y",
    }


@pytest.mark.architecture
def test_b2_same_named_attribute_on_an_unrelated_class_is_not_a_read(tmp_path: Path) -> None:
    """`other.b` on an unrelated class does not read `Rec.b`; a typed read of `Rec.b` does."""
    pkg = tmp_path / "src" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "m.py").write_text(
        "from dataclasses import dataclass\n"
        "@dataclass\nclass Rec:\n    b: int\n"
        "class Other:\n    b = 1\n"
        "def main() -> int:\n    r = Rec(b=1)\n    return Other().b + r.__class__.__name__.__len__()\n"
        "main()\n",
        encoding="utf-8",
    )
    config = tmp_path / "mypy.ini"
    config.write_text(_PLANT_MYPY_INI, encoding="utf-8")
    reached = reached_contexts(pkg)
    fields, _ = typed_reach_violations(pkg, reached, config)
    assert {v.key for v in fields} == {"B2 pkg.m.Rec.b"}
    (pkg / "m.py").write_text(
        "from dataclasses import dataclass\n"
        "@dataclass\nclass Rec:\n    b: int\n"
        "class Other:\n    b = 1\n"
        "def main() -> int:\n    r = Rec(b=1)\n    return Other().b + r.b\n"
        "main()\n",
        encoding="utf-8",
    )
    fields, _ = typed_reach_violations(pkg, reached, config)
    assert fields == []


@pytest.mark.architecture
def test_b3_flags_defaults_no_call_passes(plant_typed: tuple[set[str], set[str]]) -> None:
    """A default never passed fails; keyword, positional and entry-callback parameters do not."""
    _, params = plant_typed
    assert params == {
        "B3 plant.logic.helper_default(never)",
        "B3 plant.logic.Svc.run(third)",
        "B3 plant.logic.Conn.__init__(timeout)",
    }
    assert "B3 plant.scripted.helper_script_arg(extra)" not in params
