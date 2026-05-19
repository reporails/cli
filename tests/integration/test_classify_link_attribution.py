"""Integration coverage for link-source attribution on generic-classified files."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.platform.dto.models import ClassifiedFile

FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "fixtures" / "link-source-attribution"


def _walk_md_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.md"))


def _classify(case: str) -> tuple[Path, list[ClassifiedFile]]:
    scan_root = FIXTURE_ROOT / case
    files = _walk_md_files(scan_root)
    file_types = load_file_types("claude")
    classified = classify_files(scan_root, files, file_types, generic_scanning=True)
    return scan_root, classified


def _generic_by_name(classified: list[ClassifiedFile], name: str) -> ClassifiedFile:
    matches = [cf for cf in classified if cf.path.name == name and cf.file_type == "generic"]
    assert matches, f"expected one generic-classified file named {name!r}, got none"
    return matches[0]


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_main_link_attribution() -> None:
    """CLAUDE.md -> README.md emits a `main` link_source_type."""
    _root, classified = _classify("main-link")
    readme = _generic_by_name(classified, "README.md")
    assert readme.properties.get("link_source_type") == ["main"]
    assert readme.properties.get("loading_verb") == ["read"]
    assert readme.properties.get("link_depth") == "1"
    sources = readme.properties.get("link_source_path")
    assert isinstance(sources, list) and sources == ["CLAUDE.md"]
    # main is an eager surface -> linked file inherits session_start.
    assert readme.properties.get("loading") == "session_start"


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_skill_link_attribution() -> None:
    """SKILL.md -> architecture.md emits a `skill` link_source_type."""
    _root, classified = _classify("skill-link")
    arch = _generic_by_name(classified, "architecture.md")
    assert arch.properties.get("link_source_type") == ["skill"]
    assert arch.properties.get("loading_verb") == ["read"]
    assert arch.properties.get("link_depth") == "1"
    # skill is not in the eager source set -> on_demand.
    assert arch.properties.get("loading") == "on_demand"


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_memory_link_attribution() -> None:
    """subagent_memory MEMORY.md -> notes.md emits a `subagent_memory` source."""
    _root, classified = _classify("memory-link")
    notes = _generic_by_name(classified, "notes.md")
    assert notes.properties.get("link_source_type") == ["subagent_memory"]
    assert notes.properties.get("loading_verb") == ["read"]
    # subagent_memory is in the eager source set -> session_start.
    assert notes.properties.get("loading") == "session_start"


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_multi_source_merges_attribution() -> None:
    """Main + skill both link to shared.md -> list contains both surface types."""
    _root, classified = _classify("multi-source")
    shared = _generic_by_name(classified, "shared.md")
    assert shared.properties.get("link_source_type") == ["main", "skill"]
    sources = shared.properties.get("link_source_path")
    assert isinstance(sources, list) and "CLAUDE.md" in sources and any("SKILL.md" in s for s in sources)
    # main is eager -> session_start dominates the derivation.
    assert shared.properties.get("loading") == "session_start"


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_cycle_does_not_hang() -> None:
    """CLAUDE.md -> a -> b -> a terminates and emits both a and b as generic."""
    _root, classified = _classify("cycle")
    names = {cf.path.name: cf for cf in classified if cf.file_type == "generic"}
    assert "a.md" in names and "b.md" in names
    # a is reached at depth 1 from main and also at depth 3 from b (generic);
    # min depth wins.
    assert names["a.md"].properties.get("link_depth") == "1"
    # b is only reached at depth 2.
    assert names["b.md"].properties.get("link_depth") == "2"


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_import_vs_link_distinguishes_verb() -> None:
    """`@b.md` -> verb=imported; `[c](c.md)` -> verb=read."""
    _root, classified = _classify("import-vs-link")
    b = _generic_by_name(classified, "b.md")
    c = _generic_by_name(classified, "c.md")
    assert b.properties.get("loading_verb") == ["imported"]
    assert c.properties.get("loading_verb") == ["read"]
