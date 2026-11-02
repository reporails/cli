"""Import-graph analysis of `src/reporails_cli`: the one owner of the layer table, node map and finding detectors.

Every module maps to a node: `core/<subsystem>`, `core/platform/<layer>`, `interfaces/<x>`,
`formatters`, otherwise its top-level module or package name (such as `bundled`).
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "reporails_cli"


def core_subsystems(src: Path = SRC) -> set[str]:
    """The `core/` subfolders other than `platform/`: the subsystems."""
    core = src / "core"
    if not core.is_dir():
        return set()
    return {p.name for p in core.iterdir() if p.is_dir() and p.name not in {"platform", "__pycache__"}}


def interface_nodes(src: Path = SRC) -> set[str]:
    """The `interfaces/` subfolders: one delivery layer per interface."""
    interfaces = src / "interfaces"
    if not interfaces.is_dir():
        return set()
    return {p.name for p in interfaces.iterdir() if p.is_dir() and p.name != "__pycache__"}


PURE = ["contract", "dto", "policy"]
INFRA = ["adapters", "runtime", "config", "observability", "utils"]
SUBSYSTEMS = sorted(core_subsystems())
OUTER = [*sorted(interface_nodes()), "formatters"]

# Ring 0 is the pure core, 1 the infrastructure layers, 2 the subsystems, 3 the delivery layers.
RING = {**dict.fromkeys(PURE, 0), **dict.fromkeys(INFRA, 1), **dict.fromkeys(SUBSYSTEMS, 2), **dict.fromkeys(OUTER, 3)}

# What each platform layer may import.
ALLOWED: dict[str, set[str]] = {
    "contract": set(),
    "dto": {"contract"},
    "policy": {"contract", "dto"},
    "adapters": {"contract", "dto", "policy", "config", "observability", "utils"},
    # The merger names a server finding by its rule title; adapters never import runtime.
    "runtime": {"contract", "dto", "policy", "config", "observability", "utils", "adapters"},
    # Config checks a setting against the pure folder grammar, and locates the bundled lexicon file.
    "config": {"contract", "dto", "utils", "policy", "bundled"},
    "observability": {"contract", "dto", "config", "utils"},
    "utils": {"contract", "dto"},
    # The event bus stays light: no mapper, lint or pipeline, so the hook command starts fast.
    "eventbus": {
        "cache",
        "discovery",
        "contract",
        "dto",
        "policy",
        "adapters",
        "runtime",
        "config",
        "observability",
        "utils",
    },
    # The session view reads the event bus, the expected-loads listing and discovery; it holds no mapper,
    # lint or heal import of its own; the bundled price list is located through the `bundled` package.
    "xray": {
        "eventbus",
        "pipeline",
        "discovery",
        "cache",
        "contract",
        "dto",
        "policy",
        "adapters",
        "runtime",
        "config",
        "observability",
        "utils",
        "bundled",
    },
}

LARGE_MODULE = 800


def is_private(segment: str) -> bool:
    return segment.startswith("_") and not segment.startswith("__")


def module_name(src: Path, path: Path) -> str:
    parts = list(path.relative_to(src.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def node_of(mod: str) -> str | None:
    """Node a dotted module belongs to, or None for the package root itself."""
    parts = mod.split(".")[1:]
    if not parts:
        return None
    if parts[0] == "core" and len(parts) >= 2:
        if parts[1] == "platform":
            return parts[2] if len(parts) >= 3 else "platform"
        return parts[1]
    if parts[0] == "interfaces" and len(parts) >= 2:
        return parts[1]
    return parts[0]


def resolve(mod: str, is_pkg: bool, node: ast.ImportFrom, known: set[str]) -> list[tuple[str, str]]:
    """(target module, imported name or '') per alias."""
    if node.level:
        base = mod.split(".") if is_pkg else mod.split(".")[:-1]
        base = base[: len(base) - (node.level - 1)]
        target = ".".join(base + ([node.module] if node.module else []))
    else:
        target = node.module or ""
    out = []
    for alias in node.names:
        sub = f"{target}.{alias.name}"
        out.append((sub, "") if sub in known else (target, alias.name))
    return out


def _is_type_checking(test: ast.expr) -> bool:
    """Whether an `if` test is exactly `TYPE_CHECKING` or `<module>.TYPE_CHECKING`."""
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def type_checking_lines(tree: ast.Module) -> set[int]:
    lines: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.If) and _is_type_checking(n.test):
            for c in n.body:
                lines.update(range(c.lineno, (c.end_lineno or c.lineno) + 1))
    return lines


def sccs(graph: dict[str, set[str]]) -> list[list[str]]:
    """Strongly connected components with more than one node (Tarjan)."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on: set[str] = set()
    out: list[list[str]] = []
    counter = [0]

    def visit(v: str) -> None:
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        for w in graph.get(v, ()):
            if w not in index:
                visit(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1:
                out.append(sorted(comp))

    for v in sorted(graph):
        if v not in index:
            visit(v)
    return out


@dataclass(frozen=True)
class Import:
    """One project import: `src_mod` (in `src_node`) reaches `target` (in `dst_node`)."""

    src_mod: str
    src_node: str
    target: str
    name: str
    dst_node: str
    runtime: bool

    @property
    def private(self) -> bool:
        """Whether it reaches a `_private` module or name of another package."""
        return self.dst_node != self.src_node and (
            is_private(self.target.split(".")[-1]) or bool(self.name and is_private(self.name))
        )

    @property
    def text(self) -> str:
        """`src → target` with the package prefix dropped."""
        tgt = self.target.split(".", 1)[-1] + (f".{self.name}" if self.name else "")
        return f"{self.src_mod.split('.', 1)[-1]} → {tgt}"


@dataclass
class Graph:
    imports: list[Import] = field(default_factory=list)
    modules: dict[str, list[dict[str, object]]] = field(default_factory=lambda: defaultdict(list))
    large: list[tuple[str, str, int]] = field(default_factory=list)

    def edges(self) -> dict[tuple[str, str], list[Import]]:
        out: dict[tuple[str, str], list[Import]] = defaultdict(list)
        for imp in self.imports:
            if imp.dst_node != imp.src_node:
                out[(imp.src_node, imp.dst_node)].append(imp)
        return out


def build_graph(src: Path = SRC) -> Graph:
    """Parse every module under `src` (the package directory) into nodes and import records."""
    root = src.name
    files = sorted(p for p in src.rglob("*.py") if "__pycache__" not in p.parts)
    known = {module_name(src, p) for p in files}
    graph = Graph()
    for path in files:
        mod = module_name(src, path)
        src_node = node_of(mod)
        if src_node is None:
            continue
        text = path.read_text()
        short = mod.split(".", 1)[1]
        n_lines = text.count("\n") + 1
        graph.modules[src_node].append({"m": short, "lines": n_lines})
        if n_lines > LARGE_MODULE:
            graph.large.append((src_node, short, n_lines))
        tree = ast.parse(text)
        tc = type_checking_lines(tree)
        seen: set[tuple[str, str, bool]] = set()
        for n in ast.walk(tree):
            found: list[tuple[str, str]] = []
            if not isinstance(n, (ast.Import, ast.ImportFrom)):
                continue
            if isinstance(n, ast.Import):
                found = [(a.name, "") for a in n.names if a.name.split(".")[0] == root]
            elif n.level or (n.module or "").split(".")[0] == root:
                found = resolve(mod, path.name == "__init__.py", n, known)
            for target, name in found:
                dst = node_of(target)
                runtime = n.lineno not in tc
                if dst is None or (target, name, runtime) in seen:
                    continue
                seen.add((target, name, runtime))
                graph.imports.append(Import(mod, src_node, target, name, dst, runtime))
    return graph


def _in_constrained_node(mod: str) -> bool:
    """Whether `mod` sits in a platform layer or a `core/<subsystem>` that has a row."""
    return mod.split(".")[1:2] == ["core"] and (node_of(mod) or "") in ALLOWED


def layer_row_allows(src: str, dst: str) -> bool:
    """Whether platform layer `src` may import node `dst` (a node with no row is unconstrained)."""
    return src not in ALLOWED or dst == src or dst in ALLOWED[src]


def layer_violation_imports(graph: Graph) -> list[Import]:
    """Platform-layer imports of a node outside their layer's row (type-checking imports count)."""
    return [
        imp
        for imp in graph.imports
        if _in_constrained_node(imp.src_mod) and not layer_row_allows(imp.src_node, imp.dst_node)
    ]


def layer_violations(src: Path = SRC) -> list[str]:
    """Platform-layer modules importing a node outside their row, as report lines."""
    return sorted(
        {f"{i.text}  [{i.src_node} may not import {i.dst_node}]" for i in layer_violation_imports(build_graph(src))}
    )


@dataclass(frozen=True)
class Cycle:
    """A package cycle: its nodes and the runtime imports between them."""

    nodes: list[str]
    imports: list[Import]


def cycles(graph: Graph, nodes: set[str] | None = None) -> list[Cycle]:
    """Package cycles over runtime imports (type-checking-only imports excluded), within `nodes` when given."""
    adj: dict[str, set[str]] = defaultdict(set)
    edges = graph.edges()
    for (s, d), imps in edges.items():
        if nodes is not None and not (s in nodes and d in nodes):
            continue
        if any(i.runtime for i in imps):
            adj[s].add(d)
    return [
        Cycle(comp, [i for (s, d), imps in sorted(edges.items()) if s in comp and d in comp for i in imps if i.runtime])
        for comp in sccs(adj)
    ]


def subsystem_cycles(src: Path = SRC) -> list[str]:
    """One message per cycle among `core/` subsystems, listing the runtime imports that close it."""
    return [
        " ⇄ ".join(c.nodes) + ": " + "; ".join(sorted({i.text for i in c.imports}))
        for c in cycles(build_graph(src), core_subsystems(src))
    ]


def private_imports(graph: Graph) -> list[Import]:
    """Cross-node imports of a `_private` module or name (same-node private imports are fine)."""
    return [imp for imp in graph.imports if imp.private]


def private_reaches(src: Path = SRC) -> list[str]:
    """`private_imports` as report lines."""
    return sorted({imp.text for imp in private_imports(build_graph(src))})


def interface_cross_imports(graph: Graph, src: Path = SRC) -> list[Import]:
    """Imports of one `interfaces/<a>/` module from another `interfaces/<b>/` (type-checking imports count).

    Each interface composes the core on its own; what two interfaces share belongs in `core/` or `formatters/`.
    """
    interfaces = interface_nodes(src)
    return [
        imp
        for imp in graph.imports
        if imp.src_mod.split(".")[1:2] == ["interfaces"]
        and imp.target.split(".")[1:2] == ["interfaces"]
        and imp.src_node in interfaces
        and imp.dst_node in interfaces
        and imp.dst_node != imp.src_node
    ]


def interface_cross_reaches(src: Path = SRC) -> list[str]:
    """`interface_cross_imports` as report lines."""
    return sorted({imp.text for imp in interface_cross_imports(build_graph(src), src)})
