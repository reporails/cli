"""Integration coverage for link-source attribution on link-reached files.

Splits `generic` (`@<path>` imports — harness auto-loads) from `referenced`
(`[text](path)` markdown links — discoverable, not auto-loaded). A file
reached via both is classified `generic` (the import path's auto-load
guarantee dominates the link-only path's discoverability).
"""

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


def _by_name_and_type(classified: list[ClassifiedFile], name: str, file_type: str) -> ClassifiedFile:
    matches = [cf for cf in classified if cf.path.name == name and cf.file_type == file_type]
    assert matches, f"expected one {file_type}-classified file named {name!r}, got none"
    return matches[0]


def _referenced_by_name(classified: list[ClassifiedFile], name: str) -> ClassifiedFile:
    return _by_name_and_type(classified, name, "referenced")


def _generic_by_name(classified: list[ClassifiedFile], name: str) -> ClassifiedFile:
    return _by_name_and_type(classified, name, "generic")


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_main_link_attribution() -> None:
    """CLAUDE.md -> README.md (markdown link) classifies README as `referenced`."""
    _root, classified = _classify("main-link")
    readme = _referenced_by_name(classified, "README.md")
    assert readme.properties.get("link_source_type") == ["main"]
    assert readme.properties.get("loading_verb") == ["read"]
    assert readme.properties.get("link_depth") == "1"
    sources = readme.properties.get("link_source_path")
    assert isinstance(sources, list) and sources == ["CLAUDE.md"]
    # Markdown-link reach is NOT auto-loaded by the harness, regardless of
    # whether the source is an eager surface. `loading: discoverable`.
    assert readme.properties.get("loading") == "discoverable"


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_skill_link_attribution() -> None:
    """SKILL.md -> architecture.md (markdown link) classifies arch as `referenced`."""
    _root, classified = _classify("skill-link")
    arch = _referenced_by_name(classified, "architecture.md")
    assert arch.properties.get("link_source_type") == ["skill"]
    assert arch.properties.get("loading_verb") == ["read"]
    assert arch.properties.get("link_depth") == "1"
    assert arch.properties.get("loading") == "discoverable"


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_memory_link_attribution() -> None:
    """subagent_memory MEMORY.md -> notes.md (markdown link) classifies notes as `referenced`."""
    _root, classified = _classify("memory-link")
    notes = _referenced_by_name(classified, "notes.md")
    assert notes.properties.get("link_source_type") == ["subagent_memory"]
    assert notes.properties.get("loading_verb") == ["read"]
    # subagent_memory is an eager surface, but the link mechanism is still
    # markdown — harness doesn't auto-load the target. `discoverable`.
    assert notes.properties.get("loading") == "discoverable"


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_multi_source_merges_attribution() -> None:
    """Main + skill both link to shared.md -> classified `referenced`, source types merged."""
    _root, classified = _classify("multi-source")
    shared = _referenced_by_name(classified, "shared.md")
    assert shared.properties.get("link_source_type") == ["main", "skill"]
    sources = shared.properties.get("link_source_path")
    assert isinstance(sources, list) and "CLAUDE.md" in sources and any("SKILL.md" in s for s in sources)
    assert shared.properties.get("loading") == "discoverable"


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_cycle_does_not_hang() -> None:
    """CLAUDE.md -> a -> b -> a terminates and emits both as `referenced` (markdown links)."""
    _root, classified = _classify("cycle")
    names = {cf.path.name: cf for cf in classified if cf.file_type in ("generic", "referenced")}
    assert "a.md" in names and "b.md" in names
    # Both are reached via markdown links — `referenced`.
    assert names["a.md"].file_type == "referenced"
    assert names["b.md"].file_type == "referenced"
    # a is reached at depth 1 from main and also at depth 3 from b;
    # min depth wins.
    assert names["a.md"].properties.get("link_depth") == "1"
    # b is only reached at depth 2.
    assert names["b.md"].properties.get("link_depth") == "2"


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_import_vs_link_distinguishes_verb_and_type() -> None:
    """`@b.md` -> file_type=generic, verb=imported (auto-loaded by harness).
    `[c](c.md)` -> file_type=referenced, verb=read (discoverable only).
    """
    _root, classified = _classify("import-vs-link")
    b = _generic_by_name(classified, "b.md")
    c = _referenced_by_name(classified, "c.md")
    assert b.properties.get("loading_verb") == ["imported"]
    assert b.properties.get("loading") in ("session_start", "on_demand")
    assert c.properties.get("loading_verb") == ["read"]
    assert c.properties.get("loading") == "discoverable"
