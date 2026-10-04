"""Mutation-killing tests for core.discovery.agent_discovery decision helpers.

Targets survivors the integration-style discovery suite left open: the
out-of-tree exclusion guard, the always-skip walk pruning, the eager/nested
scope predicates, the eager-global recursive-leaf dispatch, the file_types
dict guard, and the `main` fallback-filename injection.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.discovery import agent_discovery as ad
from reporails_cli.core.discovery import walk
from reporails_cli.core.discovery.agents import DEFAULT_EXCLUDE_DIRS

# --- is_excluded (L90) ------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_is_excluded_path_outside_target_is_not_excluded() -> None:
    """A path not under `target` is not excluded (relative_to raises -> False).

    Kills: L90 `return False -> return True` in the ValueError branch.
    """
    assert ad.is_excluded(Path("/other/x.md"), Path("/target"), frozenset({"x.md"})) is False


# --- walk_glob always-skip pruning (L160) -----------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_glob_skips_always_skip_dirs(tmp_path: Path) -> None:
    """walk_glob never descends into `.git` (a default-excluded directory).

    Kills: L160 `return False -> return True` in `_descend_real`'s
    skip-name guard (the mutant would descend into `.git` and match inside it).
    """
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "CLAUDE.md").write_text("x")
    (tmp_path / "CLAUDE.md").write_text("y")

    results = walk.walk_glob(tmp_path, "CLAUDE.md", DEFAULT_EXCLUDE_DIRS)
    assert set(results) == {tmp_path / "CLAUDE.md"}


# --- case-insensitive filename matching -------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_glob_matches_filename_case_insensitively(tmp_path: Path) -> None:
    """A lowercase `claude.md` matches the `CLAUDE.md` pattern.

    Repos in the wild use both conventions and the agent specs do not mandate
    exact case, so a lowercase copy is a real instruction file.
    """
    (tmp_path / "claude.md").write_text("y")
    results = walk.walk_glob(tmp_path, "CLAUDE.md", DEFAULT_EXCLUDE_DIRS)
    assert set(results) == {tmp_path / "claude.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_ci_glob_matches_case_insensitively(tmp_path: Path) -> None:
    """ci_glob resolves a bare filename and a glob case-insensitively."""
    (tmp_path / "agents.md").write_text("a")
    assert ad.ci_glob(tmp_path, "AGENTS.md") == [tmp_path / "agents.md"]
    assert set(ad.ci_glob(tmp_path, "*.MD")) == {tmp_path / "agents.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_scan_marker_matches_lowercase_root_file(tmp_path: Path) -> None:
    """scan_marker_at detects a lowercase root instruction file."""
    from reporails_cli.core.discovery.agent_markers import scan_marker_at
    from reporails_cli.core.discovery.agents import get_known_agents

    (tmp_path / "claude.md").write_text("c")
    assert scan_marker_at(tmp_path, get_known_agents()["claude"], get_known_agents()) is True


# --- _is_eager_global (L229) ------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_is_eager_global_true_only_for_global_session_start() -> None:
    """Eager-global requires BOTH scope=global AND loading=session_start.

    Kills: L229 first `== -> !=` (scope check), the second `== -> !=` (loading
    check), and `and -> or` (the lazy-loading case must be False).
    """
    assert ad._is_eager_global({"scope": "global", "loading": "session_start"}) is True
    assert ad._is_eager_global({"scope": "global", "loading": "lazy"}) is False
    assert ad._is_eager_global({"scope": "nested", "loading": "session_start"}) is False


# --- _is_nested (L240) ------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_is_nested_only_for_nested_scope() -> None:
    """`scope: nested` is nested; anything else is not.

    Kills: L240 `== "nested" -> != "nested"`.
    """
    assert ad._is_nested({"scope": "nested"}) is True
    assert ad._is_nested({"scope": "global"}) is False


# --- glob_file_type_patterns eager-global recursive-leaf (L310) -------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_eager_global_recursive_leaf_uses_ancestor_walk(tmp_path: Path) -> None:
    """An eager-global `**/CLAUDE.md` resolves via ancestor walk (cwd only), not a
    descendant walk that would also pull in nested copies.

    Kills: L310 `eager_global and (is_recursive_leaf or is_bare_leaf)` with
    `or -> and` (the mutant drops to the descendant walk and includes sub/).
    """
    (tmp_path / "CLAUDE.md").write_text("c")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "CLAUDE.md").write_text("s")

    res = ad.glob_file_type_patterns(
        tmp_path, ["**/CLAUDE.md"], {"scope": "global", "loading": "session_start"}, DEFAULT_EXCLUDE_DIRS
    )
    assert res == [tmp_path / "CLAUDE.md"]


# --- load_config_file_types dict guard (L419) -------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_config_file_types_ignores_non_dict_file_types(tmp_path: Path) -> None:
    """A `file_types:` value that is a list (not a mapping) is ignored.

    Kills: L419 `if ft and isinstance(ft, dict) -> or` (the mutant would accept a
    list and `dict(ft)` it into a bogus mapping instead of returning None).
    """
    (tmp_path / "fakeagent").mkdir()
    (tmp_path / "fakeagent" / "config.yml").write_text("file_types:\n  - [k, v]\n")
    assert ad.load_config_file_types("fakeagent", [tmp_path]) is None


# --- _surface_include_patterns main-only fallbacks (L447) -------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_surface_include_injects_fallbacks_only_for_main() -> None:
    """Fallback filenames are injected as `**/<name>` only for the `main` surface.

    Kills: L447 `if file_type_name == "main" -> !=` (the mutant would inject them
    for every non-main surface and none for main).
    """
    cfg = SimpleNamespace(surfaces={}, agents={"codex": {"fallback_filenames": ["FOO.md"]}})
    assert ad._surface_include_patterns("codex", "main", cfg) == ["**/FOO.md"]
    assert ad._surface_include_patterns("codex", "override", cfg) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_agents_in_an_excluded_folder_are_dropped() -> None:
    from reporails_cli.core.discovery.agents import DetectedAgent, filter_agents_by_exclude_dirs

    class _Type:
        id = "claude"

    root = Path("/proj")
    agent = DetectedAgent(_Type(), [root / "CLAUDE.md", root / "scratch" / "CLAUDE.md"], [], [], [])  # type: ignore[arg-type]
    kept = filter_agents_by_exclude_dirs([agent], root, frozenset({"scratch"}))
    assert [a.instruction_files for a in kept] == [[root / "CLAUDE.md"]]
    assert filter_agents_by_exclude_dirs([agent], root, frozenset()) == [agent]
