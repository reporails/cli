"""Builds a view JSON at the x-ray design scale from a real fixture: 8 h, 5,000 calls, 60 subagents four levels deep,
30 MCP servers and bursts of 12 subagents launched together. Deterministic for a seed."""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path
from typing import Any

TEMPLATE = Path(__file__).resolve().parents[1] / "fixtures" / "xray" / "view_p4.json"
SESSION_S = 8 * 3600.0
CALLS = 5000
SERVERS = 30
SUBAGENTS = 60
LONG_NAME = "Investigate the long running flaky integration suite across every adapter and report"

Spec = tuple[str, str | None, int, float, float]


def _tree(rng: random.Random, window: float) -> list[Spec]:
    """60 subagents: three bursts of 12 under main, one of 12 under the first (depth 2), then 8 (depth 3), 4 (depth 4).
    Each burst launches inside the view's burst window."""
    out: list[Spec] = []

    def burst(parent: str, depth: int, p0: float, p1: float, size: int, tag: str) -> list[str]:
        ids = []
        for i in range(size):
            at = p0 + i * (window * 0.8) / size
            end = min(p1 - 1, at + rng.uniform(300, max(301.0, min(2400.0, p1 - at - 5))))
            out.append((f"{tag}{i}", parent, depth, round(at, 1), round(end, 1)))
            ids.append(f"{tag}{i}")
        return ids

    for k, t0 in enumerate((600.0, 9600.0, 18600.0)):
        burst("main", 1, t0, t0 + 6000, 12, f"b{k}_")

    def stretch(nid: str, length: float) -> tuple[float, float]:
        i = next(j for j, s in enumerate(out) if s[0] == nid)
        s = out[i]
        out[i] = (s[0], s[1], s[2], s[3], s[3] + length)
        return s[3], s[3] + length

    a, b = stretch("b0_0", 3000.0)
    second = burst("b0_0", 2, a + 10, b, 12, "c_")
    a, b = stretch(second[0], 1500.0)
    third = burst(second[0], 3, a + 5, b, 8, "d_")
    a, b = stretch(third[0], 600.0)
    burst(third[0], 4, a + 2, b, 4, "e_")
    assert len(out) == SUBAGENTS
    return out


PLAIN_TOOLS = [("Read", "read"), ("Edit", "edit"), ("Bash", "run")]


def _calls(
    rng: random.Random, nid: str, count: int, t0: float, t1: float, call_tpl: dict, mine: list[str]
) -> list[dict]:
    """The node's calls in time order: plain tool calls, some of them against one of its MCP servers."""
    calls = []
    for i in range(count):
        tool, cat = rng.choice(PLAIN_TOOLS)
        c = {
            **call_tpl,
            "t": round(rng.uniform(t0, t1), 1),
            "category": cat,
            "tool": tool,
            "label": f"{tool} · src/f{i % 97}.py",
            "source": None,
            "server": None,
            "failed": rng.random() < 0.04,
            "use_id": f"toolu_{nid}_{i}",
            "duration_s": round(rng.uniform(0.1, 30), 1),
            "result_tokens_est": rng.randint(20, 4000),
        }
        if rng.random() < 0.18:
            srv = rng.choice(mine)
            c.update(category="mcp", tool=f"mcp__{srv[4:]}__query", label=f"{srv[4:]} · query", source=srv, server=srv)
        calls.append(c)
    calls.sort(key=lambda c: c["t"])
    return calls


def _tools(calls: list[dict]) -> list[dict]:
    """The per-tool counts the inspector prints, calls descending."""
    tally: dict[tuple[str, str], list[int]] = {}
    for c in calls:
        e = tally.setdefault((c["tool"], c["category"]), [0, 0])
        e[0] += 1
        e[1] += int(c["failed"])
    return [
        {"tool": k[0], "category": k[1], "calls": v[0], "failed": v[1]}
        for k, v in sorted(tally.items(), key=lambda kv: -kv[1][0])
    ]


def _track(nid: str, calls: list[dict], main: bool) -> dict[str, Any]:
    fails = [c for c in calls if c["failed"]][:3]
    return {
        "node": nid,
        "calls": calls,
        "failure_runs": [{"first": c["t"], "last": c["t"] + 20, "count": 3, "call_id": c["use_id"]} for c in fails],
        "breaks": [{"start": 9000.0, "end": 14000.0}] if main else [],
    }


def _shape_detail(n: dict, idx: int, t0: float, t1: float) -> None:
    """Gives the node a context series that grows with its position, and the replies that go with it."""
    d = n["detail"]
    d["series"] = [[round(t0 + (t1 - t0) * i / 8, 1), 30000 + i * 9000 * (1 + idx % 5)] for i in range(9)]
    d["peak"] = d["series"][-1][1]
    rows = [list(d["composition"]["replies"][0]) for _ in d["series"]]
    for r, (t, tot) in zip(rows, d["series"], strict=True):
        r[0], r[1] = t, tot
    d["composition"]["replies"] = rows
    d["prompts"] = []


def _bursts(members: list[str], by: dict[str, Spec], min_size: int) -> list[dict[str, Any]]:
    groups: dict[int, list[str]] = {}
    for m in members:
        groups.setdefault(int(by[m][3] // 2000), []).append(m)
    return [
        {
            "members": g,
            "first_launch": min(by[m][3] for m in g),
            "last_return": max(by[m][4] for m in g),
            "down_tokens": 1000 * len(g),
        }
        for g in groups.values()
        if len(g) >= min_size
    ]


def _station(tpl_station: dict, nid: str, main: bool, t0: float, calls: list[dict], used: list[str]) -> dict[str, Any]:
    st = copy.deepcopy(tpl_station)
    st["node"] = nid
    st["mcp"] = [
        {"server": s, "first": sc[0]["t"], "last": sc[-1]["t"], "calls": len(sc), "back_tokens_est": 300 * len(sc)}
        for s in used
        for sc in [[c for c in calls if c["server"] == s]]
    ]
    for ld in st["loads"]:
        ld["t"] = round(t0 + 1 + (ld["t"] % 60 if main else 0), 1)
    if main:
        st["compactions"] = [{"t": 3000.0, "trigger": "auto", "before": 529000, "after": 53000}]
        st["hooks"] = [{**st["hooks"][0], "first": 1200.0, "last": 1260.0}]
    return st


def _sources(tpl: dict, servers: list[str], track: list[dict], had: dict[str, list[str]], kids: dict) -> list[dict]:
    mcp_tpl = next(s for s in tpl["sources"] if s["kind"] == "mcp")
    sources = [copy.deepcopy(s) for s in tpl["sources"] if s["kind"] != "mcp"]
    for i, sid in enumerate(servers):
        n_calls = sum(1 for t in track for c in t["calls"] if c["server"] == sid)
        sources.append(
            {
                **mcp_tpl,
                "id": sid,
                "name": f"srv-{i:02d}",
                "label": f"srv-{i:02d}",
                "had_by": had[sid],
                "tools": [["query", n_calls]],
            }
        )
    for s in sources:
        s["had_by"] = [h for h in s["had_by"] if h in kids]
    return sources


def _call_shares(spec: list[Spec]) -> list[int]:
    """Calls per node: weighted by duration, the main agent making about 30% of them."""
    rest = sum(s[4] - s[3] for s in spec[1:])
    weights = [rest * 0.3 / 0.7 if s[0] == "main" else s[4] - s[3] for s in spec]
    share = [max(1, round(CALLS * w / sum(weights))) for w in weights]
    share[0] += CALLS - sum(share)
    return share


def build(seed: int = 7) -> dict[str, Any]:
    rng = random.Random(seed)
    tpl = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    window = tpl["adapter"]["burst"]["window_s"]
    node_tpl = copy.deepcopy(tpl["nodes"][1])
    main_tpl = copy.deepcopy(tpl["nodes"][0])
    edge_tpl = tpl["edges"][0]
    st_sub = next(s for s in tpl["stations"] if s["node"] == "a1")
    st_main = next(s for s in tpl["stations"] if s["node"] == "main")
    call_tpl = tpl["track"][0]["calls"][0]

    spec: list[Spec] = [("main", None, 0, 0.0, SESSION_S), *_tree(rng, window)]
    kids: dict[str, list[str]] = {s[0]: [] for s in spec}
    for nid, par, *_ in spec:
        if par:
            kids[par].append(nid)
    by = {s[0]: s for s in spec}

    def descendants(nid: str) -> int:
        return sum(1 + descendants(k) for k in kids[nid])

    servers = [f"mcp:srv-{i:02d}" for i in range(SERVERS)]
    share = _call_shares(spec)

    nodes, edges, stations, track = [], [], [], []
    had: dict[str, list[str]] = {s: [] for s in servers}
    for idx, (nid, par, depth, t0, t1) in enumerate(spec):
        main = nid == "main"
        n = copy.deepcopy(main_tpl if main else node_tpl)
        n.update(
            id=nid,
            parent=par,
            depth=depth,
            start=t0,
            end=t1,
            children=kids[nid],
            descendants=descendants(nid),
            child_sources={},
        )
        if not main:
            n["name"] = LONG_NAME if idx % 9 == 0 else f"Subagent {nid} task"
            n["type"] = rng.choice(["Explore", "test-runner", "reviewer"])
        mine = servers if main else rng.sample(servers, 2)
        calls = _calls(rng, nid, share[idx], t0, t1, call_tpl, mine)
        n["tools"] = _tools(calls)
        used = sorted({c["server"] for c in calls if c["server"]})
        for s in used:
            had[s].append(nid)
        track.append(_track(nid, calls, main))
        _shape_detail(n, idx, t0, t1)
        n["bursts"] = _bursts(kids[nid], by, tpl["adapter"]["burst"]["min_size"])
        nodes.append(n)
        if par:
            edges.append({**edge_tpl, "from": par, "to": nid, "out_t": round(t0 - 1.5, 1), "back_t": t1})
        stations.append(_station(st_main if main else st_sub, nid, main, t0, calls, used))

    return {
        **tpl,
        "length_s": SESSION_S,
        "nodes": nodes,
        "edges": edges,
        "stations": stations,
        "track": track,
        "sources": _sources(tpl, servers, track, had, kids),
    }


def write(path: Path, seed: int = 7) -> dict[str, Any]:
    view = build(seed)
    path.write_text(json.dumps(view), encoding="utf-8")
    return view
