"""A cached per-file entry is only served to a file whose own coordinates it carries.

Two files that expand to the same content (`CLAUDE.md` holding only `@AGENTS.md`
next to `AGENTS.md`) must each report their own line numbers and import origins,
whichever file was analysed first or whether a cache exists. Byte-identical plain
files still share one entry.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.cache.map_cache import MapCache
from reporails_cli.core.mapper import pipeline as pl
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord

_AGENTS = "# Agents\n\nRun the tests.\n\nUse small commits.\n\nNever push to `main` directly.\n"


def _analyse(paths: list[Path], cache: MapCache) -> dict[str, list[tuple[int, str | None, str]]]:
    """Run the classify + cache-write steps for `paths`; return (line, imported_from, text) per file."""
    all_atoms: list[Atom] = []
    needing: list[Atom] = []
    records: list[FileRecord] = []
    for p in paths:
        chash = pl._classify_file(p, cache, all_atoms, needing, "legacy")
        records.append(FileRecord(path=p.as_posix(), content_hash=chash))
    pl._update_cache_after_embedding(cache, all_atoms, needing, records)
    out: dict[str, list[tuple[int, str | None, str]]] = {}
    for a in all_atoms:
        out.setdefault(Path(a.file_path).name, []).append((a.line, a.imported_from, a.text))
    return out


def _project(tmp_path: Path) -> tuple[Path, Path]:
    agents = tmp_path / "AGENTS.md"
    agents.write_text(_AGENTS, encoding="utf-8")
    claude = tmp_path / "CLAUDE.md"
    claude.write_text("@AGENTS.md", encoding="utf-8")
    return claude, agents


def _never_push_line(rows: list[tuple[int, str | None, str]]) -> int:
    return next(line for line, _, text in rows if "Never push" in text)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_importing_file_does_not_hand_its_coordinates_to_the_imported_file(tmp_path: Path) -> None:
    claude, agents = _project(tmp_path)
    cold_agents = _analyse([agents], MapCache(tmp_path / "ctl"))["AGENTS.md"]
    assert _never_push_line(cold_agents) == 7

    cache = MapCache(tmp_path / "shared")
    _analyse([agents, claude], cache)  # whole-project run writes entries for both
    warm = _analyse([agents], MapCache(tmp_path / "shared"))["AGENTS.md"]

    assert _never_push_line(warm) == 7
    assert [(r[0], r[1]) for r in warm] == [(r[0], r[1]) for r in cold_agents]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("order", ["importer_first", "imported_first"])
def test_each_file_keeps_its_own_coordinates_on_every_run(tmp_path: Path, order: str) -> None:
    claude, agents = _project(tmp_path)
    paths = [claude, agents] if order == "importer_first" else [agents, claude]
    results = []
    for _ in range(3):
        cache = MapCache(tmp_path / "cache")  # same on-disk cache across runs
        cache.load()
        results.append(_analyse(paths, cache))
    for res in results:
        assert _never_push_line(res["AGENTS.md"]) == 7
        assert not any(r[1] for r in res["AGENTS.md"])
        assert {r[0] for r in res["CLAUDE.md"]} == {1}
        assert {r[1] for r in res["CLAUDE.md"]} == {"AGENTS.md"}
    assert results[0] == results[1] == results[2]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_unchanged_files_are_served_from_the_cache_on_the_second_run(tmp_path: Path) -> None:
    claude, agents = _project(tmp_path)
    cache = MapCache(tmp_path / "cache")
    _analyse([claude, agents], cache)
    first = cache.size
    assert first == 2

    all_atoms: list[Atom] = []
    needing: list[Atom] = []
    for p in (claude, agents):
        pl._classify_file(p, MapCache(tmp_path / "cache"), all_atoms, needing, "legacy")
    assert needing == []
    assert cache.size == first


@pytest.mark.unit
@pytest.mark.subsys_map
def test_byte_identical_plain_files_share_one_entry_with_correct_lines(tmp_path: Path) -> None:
    a = tmp_path / "one" / "NOTES.md"
    b = tmp_path / "two" / "NOTES.md"
    for p in (a, b):
        p.parent.mkdir()
        p.write_text(_AGENTS, encoding="utf-8")

    cache = MapCache(tmp_path / "cache")
    _analyse([a, b], cache)
    assert cache.size == 1

    all_atoms: list[Atom] = []
    needing: list[Atom] = []
    pl._classify_file(b, MapCache(tmp_path / "cache"), all_atoms, needing, "legacy")
    assert needing == []
    assert _never_push_line([(x.line, x.imported_from, x.text) for x in all_atoms]) == 7
    assert {x.file_path for x in all_atoms} == {str(b)}
