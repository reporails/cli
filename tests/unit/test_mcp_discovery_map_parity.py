"""Red-first tests for the MCP discovery/map head sharing the CLI pipeline.

Mapper invocation: the MCP `build_map` must route through the shared
`map_instruction_files` warm path (daemon + whole-map cache), not a cold in-process
`map_ruleset`. Agent filter: MCP `_discover_files` must discover against the
`resolve_agent_filters` `filtered` list — the resolved, exclude-filtered agent set the CLI
check flow uses — not the raw detected list.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.interfaces.mcp import tools

pytestmark = [pytest.mark.unit, pytest.mark.subsys_map]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_build_map_routes_through_shared_warm_path(monkeypatch):
    """Surface 2: `build_map` calls the shared `map_instruction_files` builder."""
    seen = {}

    def fake_map(target, files, **_kw):
        seen["target"] = target
        seen["files"] = list(files)
        return "SENTINEL_MAP"

    monkeypatch.setattr("reporails_cli.interfaces.mcp.tools.map_instruction_files", fake_map)

    ruleset_map, mapper_error = tools.build_map(Path("/proj"), [Path("/proj/CLAUDE.md")])

    assert ruleset_map == "SENTINEL_MAP", "MCP must map via the shared warm path, not a cold map_ruleset"
    assert mapper_error is None
    assert seen["target"] == Path("/proj")
    assert seen["files"] == [Path("/proj/CLAUDE.md")]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_build_map_keeps_the_swallowed_exception_text_for_its_caller(monkeypatch):
    """REGRESSION: `build_map` still logs a swallowed `RuntimeError`/`ImportError` (unchanged),
    but must also hand its text back to the caller instead of only a bare `None` — the live
    concurrency defect surfaced to an MCP client as a generic "produced no map" because the
    real cause (a mapper exception) reached nowhere past `logger.warning`."""

    def raising_map(*_a, **_kw):
        raise RuntimeError("dictionary changed size during iteration")

    monkeypatch.setattr("reporails_cli.interfaces.mcp.tools.map_instruction_files", raising_map)

    ruleset_map, mapper_error = tools.build_map(Path("/proj"), [Path("/proj/CLAUDE.md")])

    assert ruleset_map is None
    assert mapper_error == "RuntimeError: dictionary changed size during iteration"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_discover_files_discovers_against_filtered_agents(monkeypatch, tmp_path):
    """Surface 4: discovery narrows against the resolved `filtered` set, not raw detected."""
    sentinel_filtered = ["FILTERED_AGENT"]
    captured = {}

    monkeypatch.setattr(
        "reporails_cli.core.platform.config.config.get_project_config",
        lambda _t: SimpleNamespace(default_agent="", exclude_dirs=[], exclude_files=[], generic_scanning=False),
    )
    monkeypatch.setattr(
        "reporails_cli.core.pipeline.mapping.detect_agents",
        lambda _t: ["RAW_DETECTED_AGENT"],
    )
    monkeypatch.setattr(
        "reporails_cli.core.pipeline.mapping.resolve_agent_filters",
        lambda *_a, **_k: ("claude", False, False, sentinel_filtered),
    )

    def fake_get_all(target, agents=None):
        captured["agents"] = agents
        return [tmp_path / "CLAUDE.md"]

    monkeypatch.setattr("reporails_cli.core.pipeline.mapping.get_all_scannable_files", fake_get_all)

    filter_agents, agent, _files, _file_type_by_path, _excluded, _exclusions = tools._discover_files(tmp_path)

    assert captured["agents"] == sentinel_filtered, "discovery must key off the filtered agent set"
    assert filter_agents == sentinel_filtered
    assert agent == "claude"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_prepare_and_validate_map_the_same_files_for_a_named_left_out_file(monkeypatch, tmp_path):
    """A file named in `targets` that the config leaves out is mapped by `prepare` exactly as by `validate`."""
    import asyncio

    from reporails_cli.core.discovery.agents import clear_agent_cache
    from reporails_cli.core.platform.runtime.merger import CombinedResult
    from reporails_cli.interfaces.mcp import server
    from reporails_cli.interfaces.mcp.prepare import prepare_for_path

    project = tmp_path / "proj"
    (project / "packages" / "x").mkdir(parents=True)
    (project / ".ails").mkdir()
    (project / ".ails" / "config.yml").write_text("exclude_dirs: [packages]\n", encoding="utf-8")
    (project / "CLAUDE.md").write_text("# Root\n\nAlways run the tests.\n", encoding="utf-8")
    (project / "packages" / "x" / "CLAUDE.md").write_text("# X\n\nAlways run the tests.\n", encoding="utf-8")
    clear_agent_cache()
    seen: list[tuple[Path, list[Path]]] = []

    def capture(target, files, **_kw):
        seen.append((target, sorted(files)))

    monkeypatch.setattr(tools, "is_initialized", lambda: True)
    monkeypatch.setattr(tools, "model_not_ready_error", lambda: None)
    monkeypatch.setattr(tools, "map_instruction_files", capture)
    monkeypatch.setattr(tools, "_check_and_assemble", lambda *_a, **_k: (CombinedResult(), None))
    tokens = ("packages/x/CLAUDE.md",)

    asyncio.run(server._fresh_validate_payload(str(project), tokens, project, server._CircuitState()))
    prepare_for_path(str(project), list(tokens))

    assert len(seen) == 2
    assert seen[0] == seen[1]
    assert {p.resolve() for p in seen[1][1]} >= {(project / "packages" / "x" / "CLAUDE.md").resolve()}
