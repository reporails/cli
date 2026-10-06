"""Mutation-killing behavioral tests for the cache module.

Targets the operators that survived the mutation probe: the mtime-gated
rules_fingerprint cache, structural_hash keyword predicates, ensure_dir
flags, load_file_map None guard, load_judgment_cache fingerprint gate, the
verdict-string parser's coordinate detection, and cache_judgments' skip /
reset gates. Each test asserts an OUTPUT that flips when the operator under
it is mutated (verified against the probe).

REPORAILS_HOME is isolated per test by the autouse `_isolate_home` fixture.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.cache import (
    ProjectCache,
    _parse_verdict_string,
    cache_judgments,
    rules_fingerprint,
    structural_hash,
)

# ---------------------------------------------------------------------------
# rules_fingerprint — mtime-gated cache (L57)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_rules_fingerprint_recomputes_on_mtime_change(tmp_path: Path) -> None:
    """A changed rule file (new mtime) yields a fresh fingerprint, not the cached one.

    Kills L57 `and->or` (first call would index a None cache entry) and
    `==->!=` (the stale fingerprint would be returned after a real change).
    """
    rules = tmp_path / "rules"
    rd = rules / "r1"
    rd.mkdir(parents=True)
    checks = rd / "checks.yml"
    checks.write_text("a: 1\n", encoding="utf-8")
    os.utime(checks, (1000, 1000))
    fp1 = rules_fingerprint([rules])

    checks.write_text("a: 2\n", encoding="utf-8")
    os.utime(checks, (2000, 2000))
    fp2 = rules_fingerprint([rules])

    assert fp1 != fp2


# ---------------------------------------------------------------------------
# structural_hash — keyword predicate chain (L81, L82)
# ---------------------------------------------------------------------------


def _hash_of(tmp_path: Path, name: str, text: str) -> str:
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    return structural_hash(f)


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_structural_hash_counts_always_line(tmp_path: Path) -> None:
    """A line included only via the 'ALWAYS' predicate changes the hash (L81)."""
    base = _hash_of(tmp_path, "base.md", "regular prose here\n")
    with_always = _hash_of(tmp_path, "always.md", "regular prose here\nALWAYS commit code\n")
    assert base != with_always


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_structural_hash_counts_important_line(tmp_path: Path) -> None:
    """A line included only via the 'IMPORTANT' predicate changes the hash (L82)."""
    base = _hash_of(tmp_path, "base.md", "regular prose here\n")
    with_important = _hash_of(tmp_path, "imp.md", "regular prose here\nIMPORTANT thing\n")
    assert base != with_important


# ---------------------------------------------------------------------------
# ProjectCache.ensure_dir + load_file_map guard (L126, L155)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_ensure_dir_creates_parents_and_is_idempotent(tmp_path: Path) -> None:
    """ensure_dir builds nested parents and tolerates an existing dir.

    Kills L126 `True->False`: `parents=False` fails on the first (nested)
    create; `exist_ok=False` fails on the second call.
    """
    cache = ProjectCache(tmp_path)
    cache.ensure_dir()
    cache.ensure_dir()
    assert cache.cache_dir.is_dir()


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_get_cached_files_none_when_missing(tmp_path: Path) -> None:
    """No file map -> None (L155 `is->is not` would deref None)."""
    cache = ProjectCache(tmp_path)
    assert cache.get_cached_files() is None


# ---------------------------------------------------------------------------
# load_judgment_cache — rules_fingerprint gate (L177)
# ---------------------------------------------------------------------------


def _seed_judgment_cache(tmp_path: Path) -> ProjectCache:
    cache = ProjectCache(tmp_path)
    cache.save_judgment_cache({"judgments": {"a.md": {"content_hash": "h"}}, "rules_fingerprint": "FP1"})
    return cache


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_judgment_cache_empty_fingerprint_keeps_entries(tmp_path: Path) -> None:
    """An empty fingerprint argument does NOT invalidate the cache (L177 `and->or`)."""
    cache = _seed_judgment_cache(tmp_path)
    loaded = cache.load_judgment_cache(rules_fingerprint="")
    assert loaded["judgments"] == {"a.md": {"content_hash": "h"}}


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_judgment_cache_changed_fingerprint_invalidates(tmp_path: Path) -> None:
    """A different fingerprint invalidates the cache (L177 `!=->==`)."""
    cache = _seed_judgment_cache(tmp_path)
    loaded = cache.load_judgment_cache(rules_fingerprint="FP2")
    assert loaded["judgments"] == {}


# ---------------------------------------------------------------------------
# _parse_verdict_string — coordinate detection (L252) + verdict scan (L263)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_parse_coordinate_id_width() -> None:
    """A well-formed coordinate id parses as a 3-part rule_id.

    Kills L252 `>=->>` (5-part boundary) and `==->!=` (the 4-char digit check).
    """
    assert _parse_verdict_string("CORE:S:0001:CLAUDE.md:fail") == (
        "CORE:S:0001",
        "CLAUDE.md",
        "fail",
        "",
    )


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_parse_short_id_when_too_few_parts() -> None:
    """A 4-part string is a short id, not a coordinate (L252 first `and->or`)."""
    assert _parse_verdict_string("AB:x:0001:fail") == ("AB", "x:0001", "fail", "")


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_parse_short_id_when_segment_not_digits() -> None:
    """A non-digit 4-char segment blocks coordinate detection (L252 second `and->or`)."""
    assert _parse_verdict_string("CORE:S:00x1:CLAUDE.md:fail") == (
        "CORE",
        "S:00x1:CLAUDE.md",
        "fail",
        "",
    )


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_parse_short_id_when_segment_wrong_length() -> None:
    """A 3-char segment blocks coordinate detection (L252 third `and->or`)."""
    assert _parse_verdict_string("CORE:S:001:CLAUDE.md:fail") == (
        "CORE",
        "S:001:CLAUDE.md",
        "fail",
        "",
    )


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_parse_no_verdict_returns_empty() -> None:
    """No pass/fail token -> empty tuple.

    Kills L263 `is->is not` and `or->and` (both would deref None < 1).
    """
    assert _parse_verdict_string("C6:CLAUDE.md:comment") == ("", "", "", "")


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_parse_verdict_with_no_location_returns_empty() -> None:
    """A verdict token with nothing before it -> empty tuple (L263 `or->and`)."""
    assert _parse_verdict_string("C6:pass:reason") == ("", "", "", "")


# ---------------------------------------------------------------------------
# cache_judgments — skip guards (L337) + content-change reset (L360)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_cache_judgments_skips_missing_rule_id(tmp_path: Path) -> None:
    """An entry with no rule_id is skipped, not recorded (L337 first `or->and`)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "real.md").write_text("x", encoding="utf-8")

    recorded = cache_judgments(proj, [{"rule_id": "", "location": "real.md:1", "verdict": "fail", "reason": "r"}])
    assert recorded == 0


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_cache_judgments_skips_missing_verdict(tmp_path: Path) -> None:
    """An entry with no verdict is skipped, not recorded (L337 second `or->and`)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "real.md").write_text("x", encoding="utf-8")

    recorded = cache_judgments(proj, [{"rule_id": "RA", "location": "real.md:1", "verdict": "", "reason": "r"}])
    assert recorded == 0


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_cache_judgments_resets_results_on_content_change(tmp_path: Path) -> None:
    """When file content changes, stale per-file results are dropped (L360 `!=->==`)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".git").mkdir()  # pin _find_project_root(proj) == proj
    f = proj / "file.md"
    f.write_text("v1 content", encoding="utf-8")

    assert cache_judgments(proj, [{"rule_id": "RA", "location": "file.md:1", "verdict": "fail", "reason": "r"}]) == 1

    f.write_text("v2 different content", encoding="utf-8")
    assert cache_judgments(proj, [{"rule_id": "RB", "location": "file.md:1", "verdict": "fail", "reason": "r"}]) == 1

    data = ProjectCache(proj).load_judgment_cache()
    results = data["judgments"]["file.md"]["results"]
    assert set(results.keys()) == {"RB"}


@pytest.mark.unit
@pytest.mark.subsys_caching
def test_structural_hash_reads_structure_not_frontmatter_or_fences(tmp_path: Path) -> None:
    base = "---\nname: x\n---\n# T\n\n- item\n\n```\nMUST in code\n```\n"
    other = "---\nname: y MUST\n---\n# T\n\n- item\n\n```\nNEVER in code\n```\n"
    assert _hash_of(tmp_path, "a.md", base) == _hash_of(tmp_path, "b.md", other)
    assert _hash_of(tmp_path, "c.md", base) != _hash_of(tmp_path, "d.md", base + "\nMUST run tests\n")
