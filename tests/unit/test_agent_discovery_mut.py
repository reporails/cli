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
from reporails_cli.core.discovery.agent_config import load_config_file_types
from reporails_cli.core.discovery.exclusions import RunExclusions
from reporails_cli.core.discovery.surface_config import surface_include_patterns
from tests.conftest import skip_if_case_insensitive_fs

# --- RunExclusions.covers (path outside the root) ---


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_covers_path_outside_root_is_not_covered() -> None:
    """A path not under the root is not covered, whatever name it carries."""
    assert RunExclusions.parse(Path("/target"), ["x.md"], ()).covers(Path("/other/x.md")) is False


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

    results = walk.walk_glob(tmp_path, "CLAUDE.md", RunExclusions.none(tmp_path))
    assert set(results) == {tmp_path / "CLAUDE.md"}


# --- case-insensitive filename matching -------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_glob_skips_a_wrong_case_name_on_a_case_sensitive_filesystem(tmp_path: Path) -> None:
    """A lowercase `claude.md` is not the documented `CLAUDE.md` where the filesystem tells them apart."""
    skip_if_case_insensitive_fs(tmp_path)
    (tmp_path / "claude.md").write_text("y")
    assert walk.walk_glob(tmp_path, "CLAUDE.md", RunExclusions.none(tmp_path)) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_ci_glob_matches_case_insensitively(tmp_path: Path) -> None:
    """ci_glob resolves a bare filename and a glob case-insensitively."""
    (tmp_path / "agents.md").write_text("a")
    assert ad.ci_glob(tmp_path, "AGENTS.md", RunExclusions.none(tmp_path)) == [tmp_path / "agents.md"]
    assert set(ad.ci_glob(tmp_path, "*.MD", RunExclusions.none(tmp_path))) == {tmp_path / "agents.md"}


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
    assert ad.is_eager_global({"scope": "global", "loading": "session_start"}) is True
    assert ad.is_eager_global({"scope": "global", "loading": "lazy"}) is False
    assert ad.is_eager_global({"scope": "nested", "loading": "session_start"}) is False


# --- _is_nested (L240) ------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_is_nested_only_for_nested_scope() -> None:
    """`scope: nested` is nested; anything else is not.

    Kills: L240 `== "nested" -> != "nested"`.
    """
    assert ad.is_nested({"scope": "nested"}) is True
    assert ad.is_nested({"scope": "global"}) is False


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
        tmp_path, ["**/CLAUDE.md"], {"scope": "global", "loading": "session_start"}, RunExclusions.none(tmp_path)
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
    assert load_config_file_types("fakeagent", [tmp_path]) is None


# --- _surface_include_patterns main-only fallbacks (L447) -------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_surface_include_injects_fallbacks_only_for_main() -> None:
    """Fallback filenames are injected as `**/<name>` only for the `main` surface.

    Kills: L447 `if file_type_name == "main" -> !=` (the mutant would inject them
    for every non-main surface and none for main).
    """
    cfg = SimpleNamespace(surfaces={}, agents={"codex": {"fallback_filenames": ["FOO.md"]}})
    assert surface_include_patterns("codex", "main", cfg) == ["**/FOO.md"]
    assert surface_include_patterns("codex", "override", cfg) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_agents_in_an_excluded_folder_are_dropped() -> None:
    from reporails_cli.core.discovery.agents import DetectedAgent, filter_agents_by_exclusions
    from reporails_cli.core.discovery.exclusions import RunExclusions

    class _Type:
        id = "claude"

    root = Path("/proj")
    agent = DetectedAgent(_Type(), [root / "CLAUDE.md", root / "scratch" / "CLAUDE.md"], [], [], [])  # type: ignore[arg-type]
    kept = filter_agents_by_exclusions([agent], RunExclusions.parse(root, ["scratch"], ()))
    assert [a.instruction_files for a in kept] == [[root / "CLAUDE.md"]]
    assert filter_agents_by_exclusions([agent], RunExclusions(root)) == [agent]


# --- glob_file_type_patterns path-pinned ** patterns ------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_pinned_recursive_patterns_match_the_whole_pattern(tmp_path: Path) -> None:
    """`**/<dir>/.../<file>` keeps only files whose path matches the whole pattern, while a
    bare `**/<leaf>` still finds the leaf anywhere."""
    for rel in (
        "docs/agents/openai.yaml",
        ".agents/skills/foo/agents/openai.yaml",
        "apps/web/.cursor/BUGBOT.md",
        "docs/BUGBOT.md",
        "pkg/CLAUDE.md",
    ):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    nested = {"scope": "nested"}

    def found(pattern: str) -> set[str]:
        res = ad.glob_file_type_patterns(tmp_path, [pattern], nested, RunExclusions.none(tmp_path))
        return {p.relative_to(tmp_path).as_posix() for p in res}

    assert found("**/.agents/skills/*/agents/openai.yaml") == {".agents/skills/foo/agents/openai.yaml"}
    assert found("**/.cursor/BUGBOT.md") == {"apps/web/.cursor/BUGBOT.md"}
    assert found("**/CLAUDE.md") == {"pkg/CLAUDE.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_recursive_pattern_filter_keeps_only_the_documented_filename_case(tmp_path: Path) -> None:
    """`**/AGENTS.md` skips a lowercase `agents.md` on a case-sensitive filesystem."""
    for rel in ("AGENTS.md", "svc/AGENTS.md", "pkg/agents.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    res = ad.glob_file_type_patterns(tmp_path, ["**/AGENTS.md"], {"scope": "nested"}, RunExclusions.none(tmp_path))
    assert "pkg/agents.md" not in {p.relative_to(tmp_path).as_posix() for p in res}


# --- exclusion filters keep an agent that has only rule files ----------------


class _ClaudeType:
    id = "claude"


def _agent(inst: list[Path], rules: list[Path]):
    from reporails_cli.core.discovery.agents import DetectedAgent

    return DetectedAgent(_ClaudeType(), inst, [], rules, [])  # type: ignore[arg-type]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rule_only_agent_survives_an_exclusion_that_matches_nothing() -> None:
    from reporails_cli.core.discovery.agents import filter_agents_by_exclusions
    from reporails_cli.core.discovery.exclusions import RunExclusions

    root = Path("/proj")
    rule = root / ".claude" / "rules" / "python.md"
    agent = _agent([], [rule])
    by_dirs = filter_agents_by_exclusions([agent], RunExclusions.parse(root, ["vendor"], ()))
    by_files = filter_agents_by_exclusions([agent], RunExclusions(root, files=("vendor/**",)))
    assert [a.rule_files for a in by_dirs] == [[rule]]
    assert [a.rule_files for a in by_files] == [[rule]]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rule_only_agent_loses_a_rule_file_inside_the_excluded_folder() -> None:
    from reporails_cli.core.discovery.agents import filter_agents_by_exclusions
    from reporails_cli.core.discovery.exclusions import RunExclusions

    root = Path("/proj")
    kept_rule = root / ".claude" / "rules" / "python.md"
    gone_rule = root / "vendor" / ".claude" / "rules" / "x.md"
    agent = _agent([], [kept_rule, gone_rule])
    by_dirs = filter_agents_by_exclusions([agent], RunExclusions.parse(root, ["vendor"], ()))
    by_files = filter_agents_by_exclusions([agent], RunExclusions(root, files=("vendor/**",)))
    assert [a.rule_files for a in by_dirs] == [[kept_rule]]
    assert [a.rule_files for a in by_files] == [[kept_rule]]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_agent_whose_only_instruction_file_is_excluded_keeps_its_surviving_rule_files() -> None:
    from reporails_cli.core.discovery.agents import filter_agents_by_exclusions
    from reporails_cli.core.discovery.exclusions import RunExclusions

    root = Path("/proj")
    rule = root / ".claude" / "rules" / "python.md"
    agent = _agent([root / "vendor" / "CLAUDE.md"], [rule])
    by_dirs = filter_agents_by_exclusions([agent], RunExclusions.parse(root, ["vendor"], ()))
    by_files = filter_agents_by_exclusions([agent], RunExclusions(root, files=("vendor/**",)))
    assert [(a.instruction_files, a.rule_files) for a in by_dirs] == [([], [rule])]
    assert [(a.instruction_files, a.rule_files) for a in by_files] == [([], [rule])]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_agent_whose_only_instruction_file_is_excluded_and_has_no_rule_files_is_dropped() -> None:
    from reporails_cli.core.discovery.agents import filter_agents_by_exclusions
    from reporails_cli.core.discovery.exclusions import RunExclusions

    root = Path("/proj")
    agent = _agent([root / "vendor" / "CLAUDE.md"], [])
    assert filter_agents_by_exclusions([agent], RunExclusions.parse(root, ["vendor"], ())) == []
    assert filter_agents_by_exclusions([agent], RunExclusions(root, files=("vendor/**",))) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rule_only_agent_whose_every_rule_file_is_excluded_is_dropped() -> None:
    from reporails_cli.core.discovery.agents import filter_agents_by_exclusions
    from reporails_cli.core.discovery.exclusions import RunExclusions

    root = Path("/proj")
    agent = _agent([], [root / "vendor" / ".claude" / "rules" / "x.md"])
    assert filter_agents_by_exclusions([agent], RunExclusions.parse(root, ["vendor"], ())) == []
    assert filter_agents_by_exclusions([agent], RunExclusions(root, files=("vendor/**",))) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_excluding_the_main_instruction_file_keeps_the_rule_files_through_the_pipeline(tmp_path: Path) -> None:
    from reporails_cli.core.discovery.agents import detect_agents, get_all_instruction_files
    from reporails_cli.core.discovery.exclusions import RunExclusions
    from reporails_cli.core.pipeline.mapping import resolve_agent_filters

    main = tmp_path / "CLAUDE.md"
    main.write_text("# Project\n\nRun the tests before you commit.\n", encoding="utf-8")
    rule = tmp_path / ".claude" / "rules" / "python.md"
    rule.parent.mkdir(parents=True)
    rule.write_text("# Python\n\nUse type hints on every function.\n", encoding="utf-8")

    _, _, _, filtered = resolve_agent_filters(
        "claude", detect_agents(tmp_path), tmp_path, RunExclusions(tmp_path, files=("CLAUDE.md",))
    )
    files = get_all_instruction_files(tmp_path, filtered)
    assert rule in files
    assert main not in files


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rule_only_claude_project_keeps_its_rule_file_under_a_no_op_exclusion(tmp_path: Path) -> None:
    from reporails_cli.core.discovery.agents import detect_agents, get_all_instruction_files
    from reporails_cli.core.discovery.exclusions import RunExclusions
    from reporails_cli.core.pipeline.mapping import resolve_agent_filters

    rule = tmp_path / ".claude" / "rules" / "python.md"
    rule.parent.mkdir(parents=True)
    rule.write_text("# Python\n\nUse type hints on every function.\n", encoding="utf-8")

    def checked(exclude_dirs: list[str] | None) -> list[Path]:
        exclusions = RunExclusions.parse(tmp_path, exclude_dirs or (), ())
        _, _, _, filtered = resolve_agent_filters("claude", detect_agents(tmp_path), tmp_path, exclusions)
        return get_all_instruction_files(tmp_path, filtered)

    assert checked(None) == [rule]
    assert checked(["vendor"]) == [rule]
