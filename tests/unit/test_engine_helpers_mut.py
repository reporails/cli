"""Mutation-killing behavioral tests for engine_helpers.

Covers the helper functions whose branch/boolean operators survived the
mutation probe: _find_project_root marker walk, _compute_category_summary
worst-severity tracking, _collect_body_only_paths guards, and the two
judgment-cache filters' hash/verdict gates. Each test asserts an OUTPUT that
changes when the operator under it is flipped (verified against the probe).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.cache import ProjectCache, content_hash, structural_hash
from reporails_cli.core.platform.dto.models import (
    Category,
    FileMatch,
    JudgmentRequest,
    Rule,
    RuleType,
    Severity,
    Violation,
)
from reporails_cli.core.platform.runtime.engine_helpers import (
    _collect_body_only_paths,
    _compute_category_summary,
    _filter_cached_judgments,
    _filter_dismissed_violations,
    _find_project_root,
)


def _make_rule(
    rule_id: str,
    category: Category = Category.STRUCTURE,
    yml_path: Path | None = None,
    match: FileMatch | None = None,
) -> Rule:
    return Rule(
        id=rule_id,
        title="t",
        category=category,
        type=RuleType.DETERMINISTIC,
        yml_path=yml_path,
        match=match,
    )


def _make_request(rule_id: str = "C6", location: str = "CLAUDE.md:1") -> JudgmentRequest:
    return JudgmentRequest(
        rule_id=rule_id,
        rule_title="t",
        content="x",
        location=location,
        question="q",
        criteria={"pass_condition": "x"},
        examples={"good": [], "bad": []},
        choices=["pass", "fail"],
        pass_value="pass",
        severity=Severity.MEDIUM,
        points_if_fail=-10,
    )


def _make_violation(rule_id: str = "C6", location: str = "CLAUDE.md:1") -> Violation:
    return Violation(
        rule_id=rule_id,
        rule_title="t",
        location=location,
        message="m",
        severity=Severity.MEDIUM,
    )


# ---------------------------------------------------------------------------
# _find_project_root — first_git / first_marker / return precedence
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_find_root_git_at_ancestor_not_leaf(tmp_path: Path) -> None:
    """The .git dir is at an ancestor; the closest .git wins, not the leaf.

    Kills L59 `and->or` (would set first_git on the leaf) and `is->is not`
    (would never set first_git), and L67 first `or->and`.
    """
    repo = tmp_path / "repo"
    leaf = repo / "a" / "b"
    leaf.mkdir(parents=True)
    (repo / ".git").mkdir()

    assert _find_project_root(leaf) == repo


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_find_root_marker_dir_detected(tmp_path: Path) -> None:
    """With no .git/backbone, an IDE marker dir at an ancestor is the root.

    Kills L61 `is->is not` (would never enter the marker loop, so first_marker
    stays None) and L67 second `or->and`.
    """
    repo = tmp_path / "repo"
    leaf = repo / "a" / "b"
    leaf.mkdir(parents=True)
    (repo / ".vscode").mkdir()

    assert _find_project_root(leaf) == repo


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_find_root_never_picks_the_home_directory_for_a_target_below_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A project without git below a home directory that is a git repository keeps its own folder."""
    home = tmp_path / "home"
    project = home / "work" / "proj"
    project.mkdir(parents=True)
    (home / ".git").mkdir()
    (home / ".vscode").mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # Path.home() reads USERPROFILE on Windows

    assert _find_project_root(project) == project
    assert _find_project_root(home) == home


# ---------------------------------------------------------------------------
# _compute_category_summary — worst-severity tracking (L126)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_category_summary_worst_severity(tmp_path: Path) -> None:
    """Worst (most severe) severity per category is recorded; counts add up.

    Kills L126 `or->and`: with `and` the first violation for a category hits
    `_SEVERITY_ORDER[worst[code]]` before `worst[code]` is set -> KeyError.
    """
    rules = {
        "S1": _make_rule("S1", Category.STRUCTURE),
        "S2": _make_rule("S2", Category.STRUCTURE),
    }
    violations = [
        _make_violation("S1"),  # MEDIUM
        Violation(
            rule_id="S2",
            rule_title="t",
            location="x:1",
            message="m",
            severity=Severity.CRITICAL,
        ),
    ]

    stats = _compute_category_summary(rules, violations)
    s = next(cs for cs in stats if cs.code == "S")
    assert s.total == 2
    assert s.failed == 2
    assert s.passed == 0
    assert s.worst_severity == "critical"


# ---------------------------------------------------------------------------
# _collect_body_only_paths — yml_path / match / return guards (L174/176/178)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_collect_body_only_paths_selects_freeform(tmp_path: Path) -> None:
    """Only rules with an existing yml_path AND format == 'freeform' are kept.

    Kills L174 (`is->is not`, `or->and` — both AttributeError on a None
    yml_path), L176 (`and->or` AttributeError on None match; `==->!=` selects
    the wrong format), and L178 (`or->and` returns None instead of the set).
    """
    yml_free = tmp_path / "free.yml"
    yml_free.write_text("x: 1")
    yml_front = tmp_path / "front.yml"
    yml_front.write_text("x: 1")
    yml_nomatch = tmp_path / "nomatch.yml"
    yml_nomatch.write_text("x: 1")

    group = {
        "R0": _make_rule("R0", yml_path=None, match=FileMatch(format="freeform")),
        "R1": _make_rule("R1", yml_path=yml_free, match=FileMatch(format="freeform")),
        "R2": _make_rule("R2", yml_path=yml_front, match=FileMatch(format="frontmatter")),
        "R3": _make_rule("R3", yml_path=yml_nomatch, match=None),
    }

    result = _collect_body_only_paths(group)
    assert result == {yml_free}


# ---------------------------------------------------------------------------
# _filter_dismissed_violations — use_cache gate + hash/verdict gates
# ---------------------------------------------------------------------------


def _seed_md(tmp_path: Path) -> tuple[Path, str, str]:
    md = tmp_path / "CLAUDE.md"
    md.write_text("# Instructions")
    return md, content_hash(md), structural_hash(md)


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_dismissed_use_cache_false_respected(tmp_path: Path) -> None:
    """use_cache=False returns violations untouched even when a pass is cached.

    Kills L194 `or->and`: with `and` it stops respecting use_cache=False and
    dismisses the violation via the cache.
    """
    md, ch, sh = _seed_md(tmp_path)
    ProjectCache(tmp_path).set_cached_judgment("CLAUDE.md", ch, {"C6": {"verdict": "pass"}}, structural_hash=sh)
    v = _make_violation("C6", f"{md}:1")

    result = _filter_dismissed_violations([v], tmp_path, tmp_path, use_cache=False)
    assert result == [v]


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_dismissed_stale_entry_keeps_violation(tmp_path: Path) -> None:
    """A stale cache entry (both hashes differ) does NOT dismiss the violation.

    Kills L225 both `!=->==` mutants: with `==` a fully-stale entry is treated
    as fresh and the passing verdict wrongly dismisses the violation.
    """
    md, _ch, _sh = _seed_md(tmp_path)
    ProjectCache(tmp_path).set_cached_judgment(
        "CLAUDE.md", "STALE_CONTENT", {"C6": {"verdict": "pass"}}, structural_hash="STALE_STRUCT"
    )
    v = _make_violation("C6", f"{md}:1")

    result = _filter_dismissed_violations([v], tmp_path, tmp_path, use_cache=True)
    assert result == [v]


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_dismissed_content_match_structural_mismatch_dismisses(tmp_path: Path) -> None:
    """When content hash matches (structural differs), the entry is valid: dismiss.

    Kills L225 `and->or`: with `or` the structural mismatch alone makes the
    entry look stale, so the passing verdict fails to dismiss.
    """
    md, ch, _sh = _seed_md(tmp_path)
    ProjectCache(tmp_path).set_cached_judgment(
        "CLAUDE.md", ch, {"C6": {"verdict": "pass"}}, structural_hash="STALE_STRUCT"
    )
    v = _make_violation("C6", f"{md}:1")

    result = _filter_dismissed_violations([v], tmp_path, tmp_path, use_cache=True)
    assert result == []


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_dismissed_valid_pass_is_dismissed(tmp_path: Path) -> None:
    """A fresh entry with a 'pass' verdict dismisses the violation.

    Kills L230 `==->!=`: with `!=` a passing verdict no longer dismisses.
    """
    md, ch, sh = _seed_md(tmp_path)
    ProjectCache(tmp_path).set_cached_judgment("CLAUDE.md", ch, {"C6": {"verdict": "pass"}}, structural_hash=sh)
    v = _make_violation("C6", f"{md}:1")

    result = _filter_dismissed_violations([v], tmp_path, tmp_path, use_cache=True)
    assert result == []


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_dismissed_valid_fail_is_kept(tmp_path: Path) -> None:
    """A fresh entry with a non-pass verdict keeps the violation.

    Kills L230 `and->or`: with `or` any cached result (even a fail) dismisses.
    """
    md, ch, sh = _seed_md(tmp_path)
    ProjectCache(tmp_path).set_cached_judgment("CLAUDE.md", ch, {"C6": {"verdict": "fail"}}, structural_hash=sh)
    v = _make_violation("C6", f"{md}:1")

    result = _filter_dismissed_violations([v], tmp_path, tmp_path, use_cache=True)
    assert result == [v]


# ---------------------------------------------------------------------------
# _filter_cached_judgments — use_cache gate (L245) + stale gate (L275)
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_cached_use_cache_false_keeps_request(tmp_path: Path) -> None:
    """use_cache=False keeps the request even with a matching cached pass.

    Kills L245 `or->and`: with `and` it stops honoring use_cache=False and
    drops the request via the cache.
    """
    md, ch, sh = _seed_md(tmp_path)
    ProjectCache(tmp_path).set_cached_judgment("CLAUDE.md", ch, {"C6": {"verdict": "pass"}}, structural_hash=sh)
    req = _make_request("C6", f"{md}:1")

    reqs, viols = _filter_cached_judgments([req], [], tmp_path, tmp_path, use_cache=False)
    assert reqs == [req]
    assert viols == []


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_cached_stale_entry_keeps_request(tmp_path: Path) -> None:
    """A fully-stale cache entry re-queues the request instead of dropping it.

    Kills L275 `!=->==`: with `==` a stale entry is treated as fresh and the
    passing verdict silently drops the request.
    """
    md, _ch, _sh = _seed_md(tmp_path)
    ProjectCache(tmp_path).set_cached_judgment(
        "CLAUDE.md", "STALE_CONTENT", {"C6": {"verdict": "pass"}}, structural_hash="STALE_STRUCT"
    )
    req = _make_request("C6", f"{md}:1")

    reqs, viols = _filter_cached_judgments([req], [], tmp_path, tmp_path, use_cache=True)
    assert len(reqs) == 1
    assert reqs[0] is req
    assert viols == []
