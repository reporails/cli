"""Build tmp/reporails-cli-hexagon.html: the cli's hexagonal layers from the live import graph.

All analysis comes from `scripts/import_graph.py`; this file renders it and words the findings.
"""

# ruff: noqa: C901, E501
# Rendering script: finding wording is prose, and the two builders are flat sequences of findings.
from __future__ import annotations

import ast
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import import_graph as ig

OUT = ig.ROOT / "tmp" / "reporails-cli-hexagon.html"
TEMPLATE = Path(__file__).with_name("template.html")

PURPOSE = {
    "contract": "Pure validators and typed contracts. Imports nothing inside the project.",
    "dto": "Pure data shapes, framework-agnostic.",
    "policy": "Pure decision functions returning DTOs.",
    "adapters": "Boundary translation between the pure core and wired state: HTTP client, wire payload, rule registry.",
    "runtime": "Orchestration helpers: the result merger, the torch blocker.",
    "config": "Env loading, path conventions, project and global config, the capability matrix.",
    "observability": "Structured logging and the per-stage timer.",
    "utils": "Cross-cutting helpers shared across the substrate, including the hook-config walk.",
    "cli": "The `ails` command line: Typer app, commands, the one process runner.",
    "mcp": "The MCP server the coding agents call: tools and their handlers.",
    "formatters": "Rendering of results: text, JSON, GitHub annotations, MCP views, triage.",
}


def docstring_line(path: Path) -> str:
    try:
        doc = ast.get_docstring(ast.parse(path.read_text()))
    except (SyntaxError, UnicodeDecodeError):
        return ""
    return (doc or "").strip().splitlines()[0] if doc else ""


def main() -> None:
    graph = ig.build_graph()
    private: dict[tuple[str, str], list[str]] = defaultdict(list)
    for imp in graph.imports:
        if imp.dst_node != imp.src_node and (
            ig.is_private(imp.target.split(".")[-1]) or (imp.name and ig.is_private(imp.name))
        ):
            private[(imp.src_node, imp.dst_node)].append(imp.text)

    def verdict(src: str, dst: str) -> tuple[str, str]:
        if src in ig.ALLOWED:
            if dst in ig.ALLOWED[src]:
                return "ok", ""
            return "violation", "fenced by test_layer_rules"
        if ig.RING[dst] > ig.RING[src]:
            floor = "test_subsystem_outer_imports" if ig.RING[src] == 2 else ""
            return "violation", (f"fenced by {floor}" if floor else "points outward")
        if ig.RING[dst] == ig.RING[src]:
            return "lateral", ""
        return "ok", ""

    edge_list = []
    for (s, d), imps in sorted(graph.edges().items()):
        if s not in ig.RING or d not in ig.RING:
            continue
        kind, note = verdict(s, d)
        pairs = sorted({i.text + ("" if i.runtime else "  (type-checking only)") for i in imps})
        edge_list.append({"s": s, "d": d, "n": len(pairs), "kind": kind, "note": note, "pairs": pairs})

    nodes = []
    for name, ring in ig.RING.items():
        mods = sorted(graph.modules.get(name, []), key=lambda m: -int(m["lines"]))
        if name in ig.SUBSYSTEMS:
            init = ig.SRC / "core" / name / "__init__.py"
            purpose = docstring_line(init) if init.exists() else ""
        else:
            purpose = PURPOSE.get(name, "")
        nodes.append(
            {
                "id": name,
                "ring": ring,
                "files": len(mods),
                "lines": sum(int(m["lines"]) for m in mods),
                "purpose": purpose,
                "modules": mods,
            }
        )

    findings = analyse(edge_list, private, graph)
    data = {"nodes": nodes, "edges": edge_list, "findings": findings}
    html = TEMPLATE.read_text().replace("/*__DATA__*/null", json.dumps(data))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html)
    print(f"{OUT}: {len(nodes)} nodes, {len(edge_list)} edges, {sum(e['n'] for e in edge_list)} module imports")
    for f in findings:
        print(f"  [{f['severity']}] {f['title']} :: edges={f['edges']} nodes={f['nodes']}")
        for ev in f["evidence"][:6]:
            print(f"      {ev}")


def analyse(
    edge_list: list[dict[str, object]], private: dict[tuple[str, str], list[str]], src_graph: ig.Graph
) -> list[dict[str, object]]:
    """Clean-architecture findings, most severe first."""
    findings: list[dict] = []
    by_pair = {(e["s"], e["d"]): e for e in edge_list}

    for e in edge_list:
        if e["kind"] != "violation":
            continue
        fenced = e["note"].startswith("fenced")
        findings.append(
            {
                "severity": "critical",
                "kind": "layer-rule",
                "title": f"{e['s']} imports {e['d']}, which its layer may not",
                "why": (
                    f"The platform layer table lets {e['s']} import only "
                    f"{', '.join(sorted(ig.ALLOWED.get(e['s'], set()))) or 'nothing inside the project'}. "
                    + (
                        "A test fences this rule, so it should fail the build."
                        if fenced
                        else "No architecture test fences this pair, which is why it went unnoticed."
                    )
                ),
                "nodes": [e["s"], e["d"]],
                "edges": [[e["s"], e["d"]]],
                "evidence": e["pairs"],
            }
        )

    graph: dict[str, set[str]] = defaultdict(set)
    for e in edge_list:
        if any("(type-checking only)" not in p for p in e["pairs"]):
            graph[e["s"]].add(e["d"])
    for comp in ig.sccs(graph):
        cyc = [[s, d] for (s, d) in by_pair if s in comp and d in comp and d in graph[s]]
        ev = []
        for s, d in cyc:
            ev += [f"{s} → {d}: {p}" for p in by_pair[(s, d)]["pairs"][:3]]
        findings.append(
            {
                "severity": "serious",
                "kind": "cycle",
                "title": "Package dependency cycle: " + " ⇄ ".join(comp),
                "why": (
                    "These packages import each other, directly or around a loop, so none can be understood, "
                    "tested or changed alone (Acyclic Dependencies Principle). A same-ring cycle hides which "
                    "package owns the shared concern; the fix is usually to move that concern down a ring or into one owner."
                ),
                "nodes": comp,
                "edges": cyc,
                "evidence": ev,
            }
        )

    for (s, d), pairs in sorted(private.items()):
        findings.append(
            {
                "severity": "serious",
                "kind": "private-reach",
                "title": f"{s} reaches into {d}'s private names",
                "why": (
                    "A leading underscore marks a name or module as internal to its package. Importing it from another "
                    "package couples the two through an implementation detail, so a refactor inside the owner breaks the caller. "
                    "Promote it to the owner's public surface or move the caller's need into the owner."
                ),
                "nodes": [s, d],
                "edges": [[s, d]],
                "evidence": sorted(set(pairs)),
            }
        )

    delivery = {"cli", "mcp", "formatters"}
    for (s, d), e in sorted(by_pair.items()):
        if s in delivery and d in delivery and not (s in {"cli", "mcp"} and d == "formatters"):
            wrong_way = s == "formatters"
            findings.append(
                {
                    "severity": "serious" if wrong_way else "warning",
                    "kind": "delivery-coupling",
                    "title": f"{s} depends on {d} (outer ring, sideways)",
                    "why": (
                        "Formatters render results for the interfaces; a formatter importing an interface points the dependency backwards."
                        if wrong_way
                        else "Two delivery mechanisms depending on each other means a change for one front end can break the other. "
                        "Shared needs belong in a subsystem or in formatters, which both interfaces already use."
                    ),
                    "nodes": [s, d],
                    "edges": [[s, d]],
                    "evidence": e["pairs"],
                }
            )

    ce = defaultdict(set)
    ca = defaultdict(set)
    for e in edge_list:
        ce[e["s"]].add(e["d"])
        ca[e["d"]].add(e["s"])
    inst = {n: len(ce[n]) / (len(ce[n]) + len(ca[n])) for n in ig.RING if ce[n] or ca[n]}
    for e in edge_list:
        s, d = e["s"], e["d"]
        if ig.RING[s] == ig.RING[d] == 2 and inst.get(d, 0) - inst.get(s, 0) >= 0.25:
            findings.append(
                {
                    "severity": "warning",
                    "kind": "unstable-dependency",
                    "title": f"{s} depends on the less stable {d}",
                    "why": (
                        f"Instability I = outgoing / (outgoing + incoming) package links: {s} {inst[s]:.2f}, {d} {inst[d]:.2f}. "
                        "A package should depend on packages more stable than itself (Stable Dependencies Principle); "
                        f"here changes in {d} ripple into {s}, which more of the system leans on."
                    ),
                    "nodes": [s, d],
                    "edges": [[s, d]],
                    "evidence": e["pairs"],
                }
            )

    for node, mod, n in sorted(src_graph.large, key=lambda x: -x[2]):
        findings.append(
            {
                "severity": "warning",
                "kind": "large-module",
                "title": f"{mod} is {n:,} lines",
                "why": (
                    f"A module over {ig.LARGE_MODULE} lines usually holds more than one concern, which works against one owner per concern "
                    "and makes the module hard to review. Check whether it splits along a seam that already exists."
                ),
                "nodes": [node],
                "edges": [],
                "evidence": [],
            }
        )
    rank = {"critical": 0, "serious": 1, "warning": 2}
    return sorted(findings, key=lambda f: rank[f["severity"]])


if __name__ == "__main__":
    main()
